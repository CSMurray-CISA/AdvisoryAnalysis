# Advisory Lens

Advisory Lens is a static, browser-only CVE triage dashboard. Give it a public vendor advisory, security blog, PDF, or pasted CVE list and it will:

- extract every unique CVE identifier;
- check the CISA Known Exploited Vulnerabilities catalog;
- query CVE.org, NVD, and CISA's Vulnrichment repository;
- display CISA SSVC exploitation, automatable, and technical-impact decision points;
- clearly distinguish official assessments from local inference;
- collect vendor, product, CWE, CVSS, and remediation context where available;
- sort and filter every results column; and
- export the current filtered view to CSV for Excel.

## Publish with GitHub Pages

1. Put `index.html`, `styles.css`, and `app.js` at the root of a GitHub repository.
2. In the repository, open **Settings → Pages**.
3. Choose **Deploy from a branch**, select your branch and the root (`/`) folder, then save.

There is no build step and no server-side component.

## How data access works

The app loads the KEV catalog once per page load and keeps it in memory until the tab is refreshed. It uses CISA's official `kev-data` GitHub mirror so a CISA.gov CORS rejection does not generate an error. JSON is preferred and CSV is the fallback.

Browsers cannot directly read many third-party sites because of CORS restrictions. Advisory Lens no longer attempts a direct cross-origin request. It uses two CORS-safe HTML paths, a JavaScript-capable reader, and [Jina Reader](https://github.com/jina-ai/reader) as a final fallback. Android bulletins prefer the raw HTML paths. Microsoft monthly release-note links are translated to Microsoft's official, compact Security Update Guide release API before going through a CORS-safe path; this avoids both the empty page shell and the very large monthly CVRF download. If every reader is blocked by the local network or the source site, the app keeps a visible error below the input and accepts pasted CVE identifiers in the same field.

NVD's unauthenticated API has a low public rate limit, so NVD calls are deliberately paced. A large advisory can take several minutes. CVE.org and Vulnrichment requests run in parallel while the NVD queue progresses.

## SSVC interpretation

When CISA Vulnrichment or a CISA ADP container provides SSVC values, the app labels them **Official**. If no official value exists, it may infer:

- exploitation from KEV status and explicit advisory language;
- automatable from CVSS attack vector, complexity, and user-interaction fields; and
- technical impact from CVSS impact fields and base score.

Inferred values are labeled **Inferred · confirm** and should receive analyst review. The app reports the three vulnerability-specific CISA Coordinator decision points requested here; a final CISA Coordinator decision additionally depends on stakeholder-specific mission and public-wellbeing context that a public advisory cannot determine.

## Privacy and limitations

Results and API responses stay in the browser's memory and disappear on refresh. Advisory URLs are sent to one of the public reading services described above for extraction; do not submit private or authenticated URLs. Public-source availability, CORS policies, upstream API changes, corporate web filters, and rate limits can affect results. This tool is decision support, not a compliance determination or substitute for analyst judgment.
