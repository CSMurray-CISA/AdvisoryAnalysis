const ENDPOINTS = {
  kev: [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
  ],
  cve: (id) => `https://cveawg.mitre.org/api/cve/${id}`,
  nvd: (id) => `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`,
  vulnrichment: (id) => {
    const [, year, serial] = id.split("-");
    const bucket = `${Math.floor(Number(serial) / 1000)}xxx`;
    return `https://raw.githubusercontent.com/cisagov/vulnrichment/develop/${year}/${bucket}/${id}.json`;
  },
};

const state = {
  kev: new Map(),
  kevMeta: null,
  cache: new Map(),
  results: [],
  filtered: [],
  source: "",
  advisoryText: "",
  sort: { key: "kev", direction: "desc" },
  controller: null,
  cancelled: false,
  nvdLastRequest: 0,
  nvdChain: Promise.resolve(),
  kevReady: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const el = {
  catalogState: $("#catalogState"),
  form: $("#scanForm"),
  input: $("#sourceInput"),
  scanButton: $("#scanButton"),
  demoButton: $("#demoButton"),
  progressPanel: $("#progressPanel"),
  progressKicker: $("#progressKicker"),
  progressText: $("#progressText"),
  progressBar: $("#progressBar"),
  cancelButton: $("#cancelButton"),
  workspace: $("#workspace"),
  emptyState: $("#emptyState"),
  sourceLine: $("#sourceLine"),
  totalStat: $("#totalStat"),
  kevStat: $("#kevStat"),
  activeStat: $("#activeStat"),
  impactStat: $("#impactStat"),
  tableSearch: $("#tableSearch"),
  kevFilter: $("#kevFilter"),
  exploitFilter: $("#exploitFilter"),
  impactFilter: $("#impactFilter"),
  clearFilters: $("#clearFilters"),
  body: $("#resultsBody"),
  resultCount: $("#resultCount"),
  exportButton: $("#exportButton"),
  dialog: $("#detailDialog"),
  dialogContent: $("#dialogContent"),
  dialogClose: $("#dialogClose"),
  toast: $("#toast"),
};

document.addEventListener("DOMContentLoaded", () => {
  state.kevReady = loadKevCatalog();
  bindEvents();
});

function bindEvents() {
  el.form.addEventListener("submit", (event) => {
    event.preventDefault();
    runAnalysis(el.input.value.trim());
  });
  el.demoButton.addEventListener("click", () => {
    el.input.value = "https://www.cisa.gov/news-events/alerts/2024/03/29/reported-supply-chain-compromise-affecting-xz-utils-data-compression-library-cve-2024-3094";
    el.input.focus();
  });
  el.cancelButton.addEventListener("click", cancelAnalysis);
  [el.tableSearch, el.kevFilter, el.exploitFilter, el.impactFilter].forEach((control) => control.addEventListener("input", applyFilters));
  el.clearFilters.addEventListener("click", () => {
    el.tableSearch.value = "";
    el.kevFilter.value = "all";
    el.exploitFilter.value = "all";
    el.impactFilter.value = "all";
    applyFilters();
  });
  $$('[data-sort]').forEach((button) => button.addEventListener("click", () => setSort(button.dataset.sort)));
  el.body.addEventListener("click", (event) => {
    if (event.target.closest("a")) return;
    const row = event.target.closest("tr[data-id]");
    if (row) openDetail(row.dataset.id);
  });
  el.body.addEventListener("keydown", (event) => {
    if (!["Enter", " "].includes(event.key)) return;
    const row = event.target.closest("tr[data-id]");
    if (row) {
      event.preventDefault();
      openDetail(row.dataset.id);
    }
  });
  el.exportButton.addEventListener("click", exportCsv);
  el.dialogClose.addEventListener("click", () => el.dialog.close());
  el.dialog.addEventListener("click", (event) => {
    if (event.target === el.dialog) el.dialog.close();
  });
}

async function loadKevCatalog() {
  let lastError;
  for (const url of ENDPOINTS.kev) {
    try {
      const data = await fetchJson(url, { timeout: 25000 });
      if (!Array.isArray(data.vulnerabilities)) throw new Error("Unexpected KEV format");
      state.kev = new Map(data.vulnerabilities.map((item) => [String(item.cveID || item.cveId).toUpperCase(), item]));
      state.kevMeta = { version: data.catalogVersion, released: data.dateReleased, url };
      el.catalogState.innerHTML = `<span class="state-dot"></span><span>CISA KEV ${escapeHtml(data.catalogVersion || "ready")} · ${state.kev.size.toLocaleString()} records</span>`;
      return;
    } catch (error) {
      lastError = error;
    }
  }
  el.catalogState.innerHTML = `<span class="state-dot error"></span><span>KEV catalog unavailable</span>`;
  showToast(`CISA KEV could not be loaded. KEV results will be marked unknown. ${lastError?.message || ""}`);
}

async function runAnalysis(input) {
  if (!input) return;
  cancelAnalysis(false);
  state.cancelled = false;
  state.controller = new AbortController();
  state.results = [];
  state.filtered = [];
  state.source = input;
  state.advisoryText = "";
  state.nvdLastRequest = 0;
  state.nvdChain = Promise.resolve();
  setBusy(true);
  showProgress("Reading advisory", "Looking for CVE identifiers…", 4, "advisory");

  try {
    const sourceText = isUrl(input) ? await fetchAdvisory(input) : input;
    state.advisoryText = sourceText;
    const cves = extractCves(sourceText);
    if (!cves.length) throw new Error("No CVE identifiers were found. Try another public link or paste the CVE IDs directly.");
    if (cves.length > 100) throw new Error(`This page contains ${cves.length} CVEs. The browser edition analyzes up to 100 at a time.`);
    await state.kevReady;

    markStep("advisory", "done");
    markStep("cve", "active");
    showProgress("Identifiers found", `${cves.length} unique CVE${cves.length === 1 ? "" : "s"} found. Gathering official records…`, 10, "cve");

    let completed = 0;
    const tasks = cves.map(async (id) => {
      const result = await enrichCve(id, sourceText);
      if (state.cancelled) return;
      state.results.push(result);
      completed += 1;
      const percent = 10 + Math.round((completed / cves.length) * 86);
      showProgress("Enriching CVEs", `${completed} of ${cves.length} analyzed${cves.length > 1 ? " · NVD requests are paced to respect public rate limits" : ""}`, percent, completed === cves.length ? "kev" : "nvd");
    });
    await Promise.all(tasks);
    if (state.cancelled) return;

    ["cve", "nvd", "vulnrichment", "kev"].forEach((step) => markStep(step, "done"));
    showProgress("Analysis complete", `${state.results.length} CVE records ready`, 100, "kev");
    state.results.sort((a, b) => b.kev.localeCompare(a.kev) || b.cvss - a.cvss || a.id.localeCompare(b.id));
    renderResults();
    setTimeout(() => el.progressPanel.classList.add("hidden"), 450);
  } catch (error) {
    if (error.name !== "AbortError" && !state.cancelled) showToast(error.message || "The analysis could not be completed.");
    el.progressPanel.classList.add("hidden");
  } finally {
    setBusy(false);
  }
}

function cancelAnalysis(showMessage = true) {
  if (state.controller) state.controller.abort();
  state.cancelled = true;
  if (showMessage && !el.progressPanel.classList.contains("hidden")) showToast("Analysis cancelled.");
  el.progressPanel.classList.add("hidden");
  setBusy(false);
}

async function fetchAdvisory(url) {
  const attempts = [url, `https://r.jina.ai/${url}`];
  let lastError;
  for (let index = 0; index < attempts.length; index += 1) {
    try {
      const response = await fetchWithTimeout(attempts[index], { headers: { Accept: "text/html,text/plain,application/json,application/pdf;q=0.8,*/*;q=0.5" } }, 35000);
      if (!response.ok) throw new Error(`Advisory returned HTTP ${response.status}`);
      const type = response.headers.get("content-type") || "";
      const text = await response.text();
      if (!text || text.length < 10) throw new Error("The advisory was empty");
      if (index === 0 && type.includes("text/html")) {
        const doc = new DOMParser().parseFromString(text, "text/html");
        return `${doc.title}\n${doc.body?.innerText || text}`;
      }
      return text;
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(`The advisory could not be read from this browser. Paste its CVE IDs directly instead. ${lastError?.message || ""}`);
}

async function enrichCve(id, advisoryText) {
  const kevRecord = state.kev.get(id) || null;
  const [cveRecord, vulnRecord, nvdRecord] = await Promise.all([
    safeJson(ENDPOINTS.cve(id), `cve:${id}`),
    safeJson(ENDPOINTS.vulnrichment(id), `vuln:${id}`),
    queuedNvd(id),
  ]);

  const nvdCve = nvdRecord?.vulnerabilities?.[0]?.cve || null;
  const officialSsvc = findSsvc(vulnRecord) || findSsvc(cveRecord) || findNvdSsvc(nvdCve);
  const cvss = findCvss(cveRecord, vulnRecord, nvdCve);
  const affected = findAffected(cveRecord, nvdCve, kevRecord);
  const cwes = findCwes(cveRecord, vulnRecord, nvdCve, kevRecord);
  const context = cveContext(advisoryText, id);
  const exploitation = decideExploitation(officialSsvc, kevRecord, context);
  const automatable = decideAutomatable(officialSsvc, cvss);
  const impact = decideImpact(officialSsvc, cvss);
  const description = findDescription(cveRecord, nvdCve, kevRecord);

  return {
    id,
    vendor: affected.vendor || "Unknown",
    product: affected.product || "Unknown",
    affected: affected.all,
    cwe: cwes.join(", ") || "Unknown",
    exploitation: exploitation.value,
    exploitationEvidence: exploitation.evidence,
    exploitationConfidence: exploitation.confidence,
    automatable: automatable.value,
    automatableEvidence: automatable.evidence,
    automatableConfidence: automatable.confidence,
    impact: impact.value,
    impactEvidence: impact.evidence,
    impactConfidence: impact.confidence,
    kev: kevRecord ? "yes" : state.kevMeta ? "no" : "unknown",
    kevRecord,
    cvss: cvss.score ?? null,
    cvssVersion: cvss.version || "",
    vector: cvss.vector || "",
    description,
    sources: {
      advisory: isUrl(state.source) ? state.source : "",
      cve: ENDPOINTS.cve(id),
      nvd: `https://nvd.nist.gov/vuln/detail/${id}`,
      vulnrichment: vulnRecord ? `https://github.com/cisagov/vulnrichment/blob/develop/${id.split("-")[1]}/${Math.floor(Number(id.split("-")[2]) / 1000)}xxx/${id}.json` : "",
    },
    sourceStatus: { cve: Boolean(cveRecord), nvd: Boolean(nvdCve), vulnrichment: Boolean(vulnRecord), kev: Boolean(state.kevMeta) },
  };
}

function queuedNvd(id) {
  const job = state.nvdChain.then(async () => {
    const waitMs = Math.max(0, 6500 - (Date.now() - state.nvdLastRequest));
    if (waitMs) await delay(waitMs, state.controller?.signal);
    state.nvdLastRequest = Date.now();
    return safeJson(ENDPOINTS.nvd(id), `nvd:${id}`, true);
  });
  state.nvdChain = job.catch(() => null);
  return job;
}

async function safeJson(url, cacheKey, retryRateLimit = false) {
  if (state.cache.has(cacheKey)) return state.cache.get(cacheKey);
  try {
    let response = await fetchWithTimeout(url, { headers: { Accept: "application/json" } }, 30000);
    if (retryRateLimit && [403, 429].includes(response.status)) {
      await delay(7000, state.controller?.signal);
      response = await fetchWithTimeout(url, { headers: { Accept: "application/json" } }, 30000);
    }
    if (!response.ok) return null;
    const data = await response.json();
    state.cache.set(cacheKey, data);
    return data;
  } catch (error) {
    if (error.name === "AbortError") throw error;
    return null;
  }
}

async function fetchJson(url, { timeout = 30000 } = {}) {
  const response = await fetchWithTimeout(url, { headers: { Accept: "application/json" } }, timeout);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function fetchWithTimeout(url, options = {}, timeout = 30000) {
  const localController = new AbortController();
  const timer = setTimeout(() => localController.abort(), timeout);
  const outerSignal = state.controller?.signal;
  const abort = () => localController.abort();
  if (outerSignal?.aborted) localController.abort();
  outerSignal?.addEventListener("abort", abort, { once: true });
  try {
    return await fetch(url, { ...options, signal: localController.signal, referrerPolicy: "no-referrer" });
  } finally {
    clearTimeout(timer);
    outerSignal?.removeEventListener("abort", abort);
  }
}

function findSsvc(record) {
  const containers = [...(record?.containers?.adp || []), record?.containers?.cna].filter(Boolean);
  for (const container of containers) {
    for (const metric of container.metrics || []) {
      if (String(metric?.other?.type || "").toLowerCase() !== "ssvc") continue;
      const values = normalizeOptions(metric.other.content?.options || []);
      if (values.exploitation || values.automatable || values.technicalimpact) {
        return { ...values, source: container.title || container.providerMetadata?.shortName || "CVE ADP", version: metric.other.content?.version || "" };
      }
    }
  }
  return null;
}

function findNvdSsvc(nvd) {
  const entry = nvd?.metrics?.ssvcV203?.[0]?.ssvcData;
  if (!entry) return null;
  return { ...normalizeOptions(entry.options || []), source: "NVD / CISA ADP", version: entry.version || "" };
}

function normalizeOptions(options) {
  const output = {};
  options.forEach((option) => Object.entries(option || {}).forEach(([key, value]) => { output[key.toLowerCase().replace(/\s/g, "")] = String(value).toLowerCase(); }));
  return output;
}

function findCvss(cveRecord, vulnRecord, nvd) {
  const candidates = [];
  const collect = (container, source) => (container?.metrics || []).forEach((metric) => {
    const data = metric.cvssV4_0 || metric.cvssV3_1 || metric.cvssV3_0 || metric.cvssV2_0;
    if (data) candidates.push({ data, source });
  });
  collect(cveRecord?.containers?.cna, "CVE CNA");
  (cveRecord?.containers?.adp || []).forEach((container) => collect(container, container.title || "CVE ADP"));
  (vulnRecord?.containers?.adp || []).forEach((container) => collect(container, container.title || "CISA Vulnrichment"));
  ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"].forEach((key) => (nvd?.metrics?.[key] || []).forEach((item) => candidates.push({ data: item.cvssData, source: item.source || "NVD" })));
  const chosen = candidates.find((item) => item.source.includes("CISA")) || candidates[0];
  if (!chosen) return {};
  return { score: Number(chosen.data.baseScore), version: chosen.data.version, vector: chosen.data.vectorString, data: chosen.data, source: chosen.source };
}

function findAffected(cveRecord, nvd, kevRecord) {
  const entries = (cveRecord?.containers?.cna?.affected || []).map((item) => ({ vendor: item.vendor || item.collectionURL && domainName(item.collectionURL), product: item.product || item.packageName })).filter((item) => item.vendor || item.product);
  if (!entries.length) {
    const criteria = nvd?.configurations?.flatMap((config) => config.nodes || []).flatMap((node) => node.cpeMatch || []).find((item) => item.vulnerable)?.criteria;
    if (criteria) {
      const parts = criteria.split(":");
      entries.push({ vendor: humanizeCpe(parts[3]), product: humanizeCpe(parts[4]) });
    }
  }
  if (!entries.length && kevRecord) entries.push({ vendor: kevRecord.vendorProject, product: kevRecord.product });
  const unique = [...new Map(entries.map((item) => [`${item.vendor}|${item.product}`, item])).values()];
  return { vendor: unique[0]?.vendor, product: unique[0]?.product, all: unique };
}

function findCwes(cveRecord, vulnRecord, nvd, kevRecord) {
  const values = [];
  const collectProblems = (container) => (container?.problemTypes || []).forEach((group) => (group.descriptions || []).forEach((item) => {
    const match = `${item.cweId || ""} ${item.description || ""}`.match(/CWE-\d+/i);
    if (match) values.push(match[0].toUpperCase());
  }));
  collectProblems(cveRecord?.containers?.cna);
  (cveRecord?.containers?.adp || []).forEach(collectProblems);
  (vulnRecord?.containers?.adp || []).forEach(collectProblems);
  (nvd?.weaknesses || []).forEach((group) => (group.description || []).forEach((item) => {
    const match = item.value?.match(/CWE-\d+/i);
    if (match) values.push(match[0].toUpperCase());
  }));
  (kevRecord?.cwes || []).forEach((item) => values.push(String(item).toUpperCase()));
  return [...new Set(values)];
}

function decideExploitation(ssvc, kevRecord, context) {
  if (kevRecord) return { value: "active", evidence: `Listed in the CISA KEV catalog${kevRecord.dateAdded ? ` since ${kevRecord.dateAdded}` : ""}.`, confidence: "Official · CISA KEV" };
  if (ssvc?.exploitation) return { value: normalizeExploit(ssvc.exploitation), evidence: `${ssvc.source} SSVC ${ssvc.version || "assessment"}.`, confidence: "Official SSVC" };
  if (/actively exploited|exploitation in the wild|observed exploitation|under active attack|known to be exploited/i.test(context)) return { value: "active", evidence: "The source advisory states or strongly signals active exploitation.", confidence: "Inferred from advisory" };
  if (/proof[- ]of[- ]concept|\bPoC\b|exploit code|metasploit|weaponized/i.test(context)) return { value: "poc", evidence: "The source advisory references public exploit or proof-of-concept material.", confidence: "Inferred from advisory" };
  return { value: "unknown", evidence: "No authoritative exploitation assessment or clear advisory signal was found.", confidence: "Needs analyst review" };
}

function decideAutomatable(ssvc, cvss) {
  if (ssvc?.automatable) return { value: ssvc.automatable === "yes" ? "yes" : "no", evidence: `${ssvc.source} SSVC ${ssvc.version || "assessment"}.`, confidence: "Official SSVC" };
  const data = cvss.data;
  if (data) {
    const network = data.attackVector === "NETWORK" || /\/AV:N/.test(cvss.vector || "");
    const lowComplexity = data.attackComplexity === "LOW" || /\/AC:L/.test(cvss.vector || "");
    const noInteraction = data.userInteraction === "NONE" || /\/UI:N/.test(cvss.vector || "");
    if (network && lowComplexity && noInteraction) return { value: "yes", evidence: `Inferred from ${cvss.source} CVSS: network reachable, low complexity, and no user interaction.`, confidence: "Inferred · confirm" };
    return { value: "no", evidence: `Inferred from ${cvss.source} CVSS characteristics; large-scale reliable automation is not evident.`, confidence: "Inferred · confirm" };
  }
  return { value: "unknown", evidence: "No CISA SSVC assessment or usable CVSS vector was available.", confidence: "Needs analyst review" };
}

function decideImpact(ssvc, cvss) {
  const official = ssvc?.technicalimpact || ssvc?.["technical impact"];
  if (official) return { value: official === "total" ? "total" : "partial", evidence: `${ssvc.source} SSVC ${ssvc.version || "assessment"}.`, confidence: "Official SSVC" };
  const data = cvss.data;
  if (data) {
    const highC = data.confidentialityImpact === "HIGH" || data.vulnConfidentialityImpact === "HIGH" || /\/(C|VC):H/.test(cvss.vector || "");
    const highI = data.integrityImpact === "HIGH" || data.vulnIntegrityImpact === "HIGH" || /\/(I|VI):H/.test(cvss.vector || "");
    const total = (highC && highI) || Number(cvss.score) >= 9;
    return { value: total ? "total" : "partial", evidence: `Inferred from ${cvss.source} CVSS ${cvss.version || ""} impact metrics (base score ${cvss.score}).`, confidence: "Inferred · confirm" };
  }
  return { value: "unknown", evidence: "No CISA SSVC assessment or usable impact metrics were available.", confidence: "Needs analyst review" };
}

function renderResults() {
  el.emptyState.classList.add("hidden");
  el.workspace.classList.remove("hidden");
  el.sourceLine.textContent = isUrl(state.source) ? state.source : "Pasted CVE identifiers";
  el.totalStat.textContent = state.results.length;
  el.kevStat.textContent = state.results.filter((item) => item.kev === "yes").length;
  el.activeStat.textContent = state.results.filter((item) => item.exploitation === "active").length;
  el.impactStat.textContent = state.results.filter((item) => item.impact === "total").length;
  applyFilters();
  el.workspace.scrollIntoView({ behavior: "smooth", block: "start" });
}

function applyFilters() {
  const query = el.tableSearch.value.trim().toLowerCase();
  state.filtered = state.results.filter((item) => {
    const haystack = [item.id, item.vendor, item.product, item.cwe, item.description].join(" ").toLowerCase();
    return (!query || haystack.includes(query))
      && (el.kevFilter.value === "all" || item.kev === el.kevFilter.value)
      && (el.exploitFilter.value === "all" || item.exploitation === el.exploitFilter.value)
      && (el.impactFilter.value === "all" || item.impact === el.impactFilter.value);
  });
  sortFiltered();
  renderTable();
}

function setSort(key) {
  if (state.sort.key === key) state.sort.direction = state.sort.direction === "asc" ? "desc" : "asc";
  else state.sort = { key, direction: "asc" };
  $$('[data-sort]').forEach((button) => button.classList.toggle("active", button.dataset.sort === key));
  sortFiltered();
  renderTable();
}

function sortFiltered() {
  const { key, direction } = state.sort;
  const factor = direction === "asc" ? 1 : -1;
  state.filtered.sort((a, b) => {
    let left = sortValue(a, key);
    let right = sortValue(b, key);
    if (typeof left === "number" || typeof right === "number") return ((left ?? -1) - (right ?? -1)) * factor;
    return String(left).localeCompare(String(right)) * factor;
  });
}

function sortValue(item, key) {
  if (key === "id") return item.id;
  if (key === "vendor") return `${item.vendor} ${item.product}`;
  if (key === "cwe") return item.cwe;
  if (key === "exploitation") return { active: 3, poc: 2, none: 1, unknown: 0 }[item.exploitation];
  if (key === "automatable") return { yes: 2, no: 1, unknown: 0 }[item.automatable];
  if (key === "impact") return { total: 2, partial: 1, unknown: 0 }[item.impact];
  if (key === "kev") return { yes: 2, no: 1, unknown: 0 }[item.kev];
  if (key === "cvss") return item.cvss;
  return item[key];
}

function renderTable() {
  if (!state.filtered.length) {
    el.body.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:35px;color:var(--faint)">No results match these filters.</td></tr>`;
  } else {
    el.body.innerHTML = state.filtered.map((item) => `
      <tr data-id="${item.id}" tabindex="0">
        <td><a class="cve-link" href="https://www.cve.org/CVERecord?id=${item.id}" target="_blank" rel="noreferrer">${item.id}</a></td>
        <td class="vendor-cell"><strong title="${escapeHtml(item.vendor)}">${escapeHtml(item.vendor)}</strong><span title="${escapeHtml(item.product)}">${escapeHtml(item.product)}</span></td>
        <td class="mono">${escapeHtml(item.cwe)}</td>
        <td>${badge(item.exploitation)}<small class="confidence">${shortConfidence(item.exploitationConfidence)}</small></td>
        <td>${badge(item.automatable)}<small class="confidence">${shortConfidence(item.automatableConfidence)}</small></td>
        <td>${badge(item.impact)}<small class="confidence">${shortConfidence(item.impactConfidence)}</small></td>
        <td>${badge(item.kev, "kev")}${item.kevRecord?.dateAdded ? `<small class="confidence">Added ${escapeHtml(item.kevRecord.dateAdded)}</small>` : ""}</td>
        <td class="mono">${item.cvss == null ? "—" : `${item.cvss.toFixed(1)} <small class="confidence">v${escapeHtml(item.cvssVersion)}</small>`}</td>
        <td><button class="row-action" type="button" aria-label="View ${item.id} details">›</button></td>
      </tr>`).join("");
  }
  el.resultCount.textContent = `${state.filtered.length} of ${state.results.length} result${state.results.length === 1 ? "" : "s"}`;
}

function openDetail(id) {
  const item = state.results.find((result) => result.id === id);
  if (!item) return;
  const sourceItems = [
    item.sources.advisory && ["Source advisory", item.sources.advisory, true],
    ["CVE.org record", `https://www.cve.org/CVERecord?id=${item.id}`, item.sourceStatus.cve],
    ["NVD record", item.sources.nvd, item.sourceStatus.nvd],
    item.sources.vulnrichment && ["CISA Vulnrichment", item.sources.vulnrichment, item.sourceStatus.vulnrichment],
    ["CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", item.kev === "yes"],
  ].filter(Boolean);
  el.dialogContent.innerHTML = `<div class="detail">
    <p class="eyebrow">CISA SSVC analysis</p>
    <h2>${item.id}</h2>
    <p class="detail-subtitle">${escapeHtml(item.vendor)} · ${escapeHtml(item.product)}</p>
    <div class="detail-grid">
      ${detailMetric("Exploitation", item.exploitation, item.exploitationConfidence)}
      ${detailMetric("Automatable", item.automatable, item.automatableConfidence)}
      ${detailMetric("Technical impact", item.impact, item.impactConfidence)}
      ${detailMetric("CISA KEV", item.kev, item.kevRecord?.dateAdded ? `Added ${item.kevRecord.dateAdded}` : "Catalog checked")}
    </div>
    <section class="detail-section"><h3>Vulnerability summary</h3><p>${escapeHtml(item.description || "No English-language description was available from the queried records.")}</p></section>
    <section class="detail-section"><h3>SSVC evidence</h3>
      <div class="source-list">
        ${evidenceRow("Exploitation", item.exploitationEvidence)}
        ${evidenceRow("Automatable", item.automatableEvidence)}
        ${evidenceRow("Technical impact", item.impactEvidence)}
      </div>
      ${(item.exploitationConfidence.includes("Inferred") || item.automatableConfidence.includes("Inferred") || item.impactConfidence.includes("Inferred")) ? `<div class="note-box">One or more values are inferred from CVSS or advisory language because no CISA Vulnrichment SSVC assessment was available. Confirm inferred values before using them for policy or remediation decisions.</div>` : ""}
    </section>
    <section class="detail-section"><h3>Technical context</h3><p><strong>CWE:</strong> ${escapeHtml(item.cwe)}<br><strong>CVSS:</strong> ${item.cvss == null ? "Not available" : `${item.cvss.toFixed(1)} (v${escapeHtml(item.cvssVersion)})`}<br><strong>Vector:</strong> <span class="mono">${escapeHtml(item.vector || "Not available")}</span></p></section>
    ${item.kevRecord ? `<section class="detail-section"><h3>KEV remediation</h3><p>${escapeHtml(item.kevRecord.requiredAction || "Refer to the CISA KEV entry for required action.")} ${item.kevRecord.dueDate ? `<br><strong>Federal due date:</strong> ${escapeHtml(item.kevRecord.dueDate)}` : ""}</p></section>` : ""}
    <section class="detail-section"><h3>Evidence sources</h3><div class="source-list">${sourceItems.map(([label, url, found]) => `<div class="source-item"><span>${escapeHtml(label)} · ${found ? "used" : "checked"}</span><a href="${escapeAttr(url)}" target="_blank" rel="noreferrer">Open ↗</a></div>`).join("")}</div></section>
  </div>`;
  el.dialog.showModal();
}

function exportCsv() {
  const rows = state.filtered.length ? state.filtered : state.results;
  if (!rows.length) return;
  const headers = ["CVE", "Vendor", "Product", "CWE", "Exploitation", "Exploitation evidence", "Automatable", "Automatable evidence", "Technical impact", "Impact evidence", "CISA KEV", "KEV date added", "CVSS", "CVSS version", "CVSS vector", "Description", "Advisory"];
  const data = rows.map((item) => [item.id, item.vendor, item.product, item.cwe, item.exploitation, item.exploitationEvidence, item.automatable, item.automatableEvidence, item.impact, item.impactEvidence, item.kev, item.kevRecord?.dateAdded || "", item.cvss ?? "", item.cvssVersion, item.vector, item.description, state.source]);
  const csv = [headers, ...data].map((row) => row.map(csvCell).join(",")).join("\r\n");
  const blob = new Blob(["\ufeff", csv], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `advisory-lens-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  showToast(`Exported ${rows.length} row${rows.length === 1 ? "" : "s"} to CSV.`);
}

function extractCves(text) {
  const matches = String(text).match(/CVE[-\s–—_]?\d{4}[-\s–—_]?\d{4,19}/gi) || [];
  return [...new Set(matches.map((value) => value.toUpperCase().replace(/[\s–—_]+/g, "-")).filter((value) => /^CVE-\d{4}-\d{4,19}$/.test(value)))].sort();
}

function cveContext(text, id) {
  const lower = String(text).toLowerCase();
  const index = lower.indexOf(id.toLowerCase());
  if (index < 0) return String(text).slice(0, 4000);
  return String(text).slice(Math.max(0, index - 1200), index + 1800);
}

function findDescription(cveRecord, nvd, kevRecord) {
  const descriptions = cveRecord?.containers?.cna?.descriptions || [];
  return descriptions.find((item) => item.lang === "en")?.value || nvd?.descriptions?.find((item) => item.lang === "en")?.value || kevRecord?.shortDescription || "";
}

function normalizeExploit(value) {
  if (["active", "active exploitation"].includes(value)) return "active";
  if (["poc", "proof of concept", "proof-of-concept"].includes(value)) return "poc";
  if (value === "none") return "none";
  return "unknown";
}

function showProgress(kicker, text, percent, activeStep) {
  el.progressPanel.classList.remove("hidden");
  el.progressKicker.textContent = kicker;
  el.progressText.textContent = text;
  el.progressBar.style.width = `${percent}%`;
  markStep(activeStep, "active");
}

function markStep(name, status) {
  const node = $(`[data-step="${name}"]`);
  if (!node) return;
  node.classList.remove("active", "done");
  node.classList.add(status);
}

function setBusy(busy) {
  el.scanButton.disabled = busy;
  el.scanButton.querySelector(".button-label").textContent = busy ? "Analyzing…" : "Analyze";
}

function showToast(message) {
  el.toast.textContent = message;
  el.toast.classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => el.toast.classList.remove("show"), 5200);
}

function badge(value, extra = "") {
  const label = value === "poc" ? "Public PoC" : value === "yes" && extra === "kev" ? "Listed" : value === "no" && extra === "kev" ? "Not listed" : titleCase(value);
  return `<span class="badge ${escapeAttr(value)} ${escapeAttr(extra)}"><i class="evidence-dot"></i>${escapeHtml(label)}</span>`;
}

function detailMetric(label, value, note) {
  return `<div class="detail-metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(titleCase(value))}</strong><small class="confidence">${escapeHtml(note)}</small></div>`;
}

function evidenceRow(label, text) {
  return `<div class="source-item"><span>${escapeHtml(label)}</span><span>${escapeHtml(text)}</span></div>`;
}

function shortConfidence(value) {
  if (value.startsWith("Official")) return "Official";
  if (value.startsWith("Inferred")) return "Inferred";
  return "Review";
}

function humanizeCpe(value = "") { return decodeURIComponent(value).replace(/[_-]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function domainName(url) { try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return ""; } }
function titleCase(value = "") { return String(value).replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function isUrl(value) { try { return ["http:", "https:"].includes(new URL(value).protocol); } catch { return false; } }
function delay(ms, signal) { return new Promise((resolve, reject) => { if (signal?.aborted) { reject(new DOMException("Aborted", "AbortError")); return; } const timer = setTimeout(resolve, ms); signal?.addEventListener("abort", () => { clearTimeout(timer); reject(new DOMException("Aborted", "AbortError")); }, { once: true }); }); }
function csvCell(value) { const text = String(value ?? ""); return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text; }
function escapeHtml(value) { return String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]); }
function escapeAttr(value) { return escapeHtml(value); }
