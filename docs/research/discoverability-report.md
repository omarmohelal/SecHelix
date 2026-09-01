# SecHelix discoverability report

**Date:** 2026-09-01 · **Canonical domain:** https://sechelix.com (live, verified certificate)

---

## 1. What exists

| Surface | State |
| --- | --- |
| Canonical domain | `sechelix.com`, DNS propagated, certificate valid |
| `sitemap.xml` | **44 URLs**, docs routes derived from the nav manifest so they cannot drift |
| `robots.txt` | Allows `*`, `OAI-SearchBot`, `PerplexityBot`; disallows `/admin/`, `/api/admin/` |
| `/llms.txt` | Present, updated with the current inventory and the claims policy |
| `/faq` | Present with FAQ JSON-LD |
| Structured data | `Organization`, `SoftwareApplication`, `SoftwareSourceCode`, `WebSite` |
| Open Graph / Twitter | Branded 1200×630 card, 140 KB |
| `security.txt` | Served at `/.well-known/security.txt` |
| Per-route canonicals | Set on every route; the earlier root-inheritance bug is fixed |
| Security headers | Full CSP, frame-ancestors none, HSTS, nosniff, referrer policy, permissions policy |
| Source maps | Disabled in production; asserted by `check:privacy` |

## 2. What changed in this pass

**Documentation became indexable content.** `/docs` was a single landing page. It is now a
**34-page hierarchy** across Getting Started, Using SecHelix, Core Concepts, Tooling, Reference,
Teams, and Research, with a sidebar, breadcrumbs, previous/next navigation, an on-page outline, and
client-side search. Every page carries its own title, description, and canonical URL, and every URL
is in the sitemap.

This matters more than any metadata change: it converts one page competing for a broad term into
34 pages that each answer a specific query — *"security audit skill for Claude Code"*,
*"BOLA IDOR authorization testing"*, *"MCP security audit"*, *"evidence-first AppSec"*,
*"security regression testing"* — with genuine technical content behind each.

**New credibility surfaces.** `/case-studies` publishes the first recorded audit. `/benchmarks` now
states the measurement blocker explicitly rather than showing an unexplained placeholder. Both are
in the sitemap and cross-linked from docs and `llms.txt`.

**`llms.txt` refreshed** with the current inventory (12 gold packs, 33 fixtures / 66 cases, 73-node
knowledge graph, 1 case study) and an explicit instruction that the committed keyword baseline must
never be cited as SecHelix performance. Answer engines that read this file get the honest framing
rather than inferring capability from catalog size.

## 3. Deliberate non-actions

- **No keyword stuffing.** Metadata keyword lists were left as-is; they are already at the edge of
  useful.
- **No thin SEO pages.** Every docs page was written from the framework repository's real content.
  Pages that would have had nothing to say were not created.
- **No install-count or vanity badge.** There is no reliable public source for it, and a fabricated
  or misleading adoption signal on a security product is worse than no badge.
- **No comparison pages.** "SecHelix vs X" pages rank well and would require accuracy claims the
  project cannot yet support.

## 4. Verified

```
sitemap.xml            44 <loc> entries
route spot-check       / /docs /docs/getting-started/installation
                       /docs/concepts/evidence-standard /docs/reference/schemas
                       /docs/teams/ci-cd /docs/research/benchmark-status
                       /case-studies /workbench /benchmarks /faq   → all 200
lint / typecheck        clean
build                   50 routes emitted, static
check:privacy           private origin, no production source maps
```

## 5. Remaining gaps

- **No measured Core Web Vitals.** The site is static, dependency-light and image-light, but LCP /
  INP / CLS have not been measured on the deployed domain.
- **No per-route Open Graph images.** All routes share one card.
- **`sitemap.lastModified` is a hardcoded date** rather than derived from content changes.
- **No `BreadcrumbList` or `TechArticle` structured data** on docs pages, though the visual
  breadcrumbs exist.
- **Search is client-side over titles and descriptions only**, not full text.
- **WebKit/Safari untested** — the same gap the previous QA recorded.
