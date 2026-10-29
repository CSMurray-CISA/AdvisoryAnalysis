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

The app loads the KEV catalog once per page load and keeps it in memory until the tab is refreshed. It tries CISA's official feed first and CISA's official `kev-data` GitHub mirror second.

Browsers cannot directly read many third-party sites because of CORS restrictions. Advisory Lens first tries the source URL directly, then uses the public [Jina Reader](https://github.com/jina-ai/reader) endpoint to convert the page or PDF to text. If both methods are blocked, paste the CVE identifiers directly into the same input.

NVD's unauthenticated API has a low public rate limit, so NVD calls are deliberately paced. A large advisory can take several minutes. CVE.org and Vulnrichment requests run in parallel while the NVD queue progresses.

## SSVC interpretation

When CISA Vulnrichment or a CISA ADP container provides SSVC values, the app labels them **Official**. If no official value exists, it may infer:

- exploitation from KEV status and explicit advisory language;
- automatable from CVSS attack vector, complexity, and user-interaction fields; and
- technical impact from CVSS impact fields and base score.

Inferred values are labeled **Inferred · confirm** and should receive analyst review. The app reports the three vulnerability-specific CISA Coordinator decision points requested here; a final CISA Coordinator decision additionally depends on stakeholder-specific mission and public-wellbeing context that a public advisory cannot determine.

## Privacy and limitations

Results and API responses stay in the browser's memory and disappear on refresh. When the direct fetch fails, the source URL is sent to Jina Reader for text extraction. Public-source availability, CORS policies, upstream API changes, and rate limits can affect results. This tool is decision support, not a compliance determination or substitute for analyst judgment.
