# SEO Audit

Use for an explicitly requested technical SEO review or repair of an authorized website. This is an agent-guided quality workflow, not a CLI scanner or a security certification. Read the companion cleanup workflow only if cleanup is also requested.

## Scope and evidence

Record the revision, framework/version, deployment origin, locales, public route templates, dynamic content sources, intended indexability, and available runtime/Search Console access. Start with source and configuration; inspect built HTML, rendered DOM, response headers and representative routes when available. Enumerate all route templates and state how many URLs were actually inspected. Sampling is not an entire-site crawl.

Use bounded, read-only requests to authorized hosts. Referenced third-party URLs do not authorize crawling their sites. Record external-link checks that are unavailable as UNKNOWN or BLOCKED, not broken. Never execute checkout, logout, deletion or other state-changing URLs as a link check.

For every check report PASS, FAIL, UNKNOWN, NOT_APPLICABLE or BLOCKED, with an exact path/line or URL, evidence artifact, observed and expected behavior, impact, priority, proposed fix, risk, and verification. Missing runtime evidence must remain explicit. A source fix is not proof of deployment or indexing.

## Checklist

| ID | Check | Decision and verification |
|---|---|---|
| SEO-01 | Indexability / noindex | Compare intended indexability with meta robots, googlebot and X-Robots-Tag at page, template, server and CDN layers. Remove accidental noindex only from intended public pages; preserve intentional exclusions for account, checkout, internal search and staging as appropriate. Authentication protects private data; noindex does not. |
| SEO-02 | Meta titles | Give public pages descriptive, distinct titles from the correct content/locale; check fallbacks, escaping and duplicates in generated output. Avoid keyword stuffing or treating a character target as a ranking guarantee. |
| SEO-03 | Meta descriptions | Write accurate page-specific summaries and sensible fallbacks. Verify generated output; search engines can choose another snippet. |
| SEO-04 | Image alt text | Meaningful images need contextual alternatives; decorative images use empty alt. Functional images describe the action. Do not infer unseen image contents or stuff keywords. |
| SEO-05 | Core Web Vitals | Measure LCP, INP and CLS with device, URL, date and lab/field provenance. Good field targets at the 75th percentile: LCP <= 2.5 s, INP <= 200 ms, CLS <= 0.1. Lighthouse/TBT is not field INP. Missing field data remains UNKNOWN. |
| SEO-06 | sitemap.xml | Generate from the authoritative public content source; include canonical, indexable, successful absolute URLs only. Exclude drafts/private pages, redirects and error URLs. Validate XML escaping, locale handling, accurate lastmod and sitemap indexes where needed; fetch the deployed sitemap. |
| SEO-07 | og:image | Verify absolute public image URL, successful fetch, correct MIME type and suitable dimensions; include coherent Open Graph title, description, URL and image alternative text. Check representative shares without inventing preview results. |
| SEO-08 | Broken links | Check internal pages, assets, anchors and redirect chains, including dynamic route parameters. Distinguish 404/410 from 401/403, rate limits, timeouts and HEAD rejection; use safe GET where appropriate. Repair the source link or give a relevant redirect, never blanket-redirect missing pages to home. |
| SEO-09 | Heading hierarchy | Use headings for document structure, not visual sizing; inspect shared layouts and page sections together. Keep one descriptive primary h1 per page as this workflow's authoring convention, not a claimed universal Google ranking rule. |
| SEO-10 | Backlink strategy | Produce a prioritized plan for relevant editorial mentions, original useful resources, legitimate integrations/directories and reclaiming broken mentions. Include target fit, proposed asset, effort, owner and measurement. No bought links, spam, fabricated endorsements or automatic outreach/publication. |
| SEO-11 | URL slugs | Prefer stable readable slugs. Before changes inventory inbound/internal references and define old-to-new permanent redirects; preserve parameters that affect behavior, update canonical/sitemap/locale links and check loops. Avoid cosmetic churn of established URLs. |
| SEO-12 | Internal links | Use descriptive crawlable anchors to canonical relevant pages, breadcrumbs and useful related content. Find orphan public pages against the route inventory; preserve navigation and avoid unrelated link stuffing. |
| SEO-13 | Canonical tags | Verify one coherent absolute canonical per applicable page and agreement with redirects, sitemap, locales and content. Do not canonicalize distinct pages or pagination indiscriminately to the home/first page. Canonical is a signal, not access control or guaranteed indexing. |
| SEO-14 | HTTPS | Inspect HTTP-to-HTTPS redirects, certificates, mixed content, proxy/origin behavior and HTTPS canonical links. Prevent redirect loops; do not enable irreversible HSTS preload/subdomain coverage without verifying scope and authorization. |
| SEO-15 | Image compression | Inventory all served images and optimize those with measurable savings using suitable format, dimensions and responsive variants. Preserve originals where needed, transparency, animation and quality; avoid enlarging already optimized files. Reserve dimensions; lazy-load offscreen images, not the LCP hero. Compare bytes and appearance. |
| SEO-16 | Schema markup | Use applicable structured-data types matching visible, truthful content; validate syntax and applicable rich-result requirements. Never fabricate reviews, prices, availability or ratings. Valid markup does not guarantee a rich result. |
| SEO-17 | Search Console | Inspect the correct property and verified ownership when access exists; distinguish verification, sitemap submission and actual indexing. Without access, provide exact setup steps and mark BLOCKED; never invent verification tokens, DNS changes, submission or indexing success. |
| SEO-18 | One h1 | Inspect rendered mobile/desktop variants and shared headers for duplicate h1 elements; retain a meaningful main heading and adjust styling independently of semantics. Apply the convention from SEO-09. |
| SEO-19 | robots.txt | Serve valid root-level rules and the correct sitemap location. Check production/staging separation and rendering-resource access. A crawl block can prevent a crawler from seeing noindex; robots.txt is neither reliable deindexing nor authentication. |
| SEO-20 | Mobile responsiveness | Inspect representative templates at narrow and wide viewports: overflow, navigation, forms, dialogs, touch targets, text resizing and layout shifts. Check interactive states and accessible content parity, not screenshots alone. |

## Fix and verify

Prioritize accidental public deindexing, bad redirects, broken navigation and mobile blockers, then shared metadata/content templates, then measured performance and discoverability improvements. Record dependencies before changing slugs, redirects, sitemap and canonicals together. Keep focused reversible commits and compare the same routes and measurement conditions before/after. Stop optional retesting after the affected behavior and required gates are verified.

Deliver a coverage matrix for all 20 IDs, prioritized remediation backlog, before/after evidence, deferred access-dependent actions, and a backlink strategy. Report SEO completion independently from the existing security gate; SEO PASS must never imply security PASS or guaranteed rankings.

## Primary references

Checked 2026-09-13; consult current official guidance when decisions depend on changing search behavior.

- [Google: noindex](https://developers.google.com/search/docs/crawling-indexing/block-indexing)
- [Google: robots.txt](https://developers.google.com/search/docs/crawling-indexing/robots/intro)
- [Google: build a sitemap](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap)
- [Web Vitals and field/lab measurement](https://web.dev/articles/vitals)
- [Google: spam policies](https://developers.google.com/search/docs/essentials/spam-policies)
