# SecHelix domain launch checklist

Status: preparation only. Do not purchase, configure, or deploy a domain without
operator approval. Candidate names include `sechelix.dev`, `sechelix.com`, and
`sechelix.ai`; availability and trademark review must be checked at decision time.

## Ownership and DNS

- [ ] Confirm registrant, billing owner, renewal owner, recovery contacts, and MFA.
- [ ] Enable registry/domain lock and document break-glass recovery.
- [ ] Choose the canonical apex or `www` hostname; redirect the other permanently.
- [ ] Configure the minimum A/AAAA/ALIAS/CNAME records required by the approved host.
- [ ] Remove stale verification/TXT records after use where the provider permits.
- [ ] Enable DNSSEC when supported and record the rollover procedure.
- [ ] Set conservative TTLs for launch, then increase after stabilization.

## HTTPS and hosting

- [ ] Provision and validate certificates for apex, `www`, and intentional subdomains only.
- [ ] Force HTTPS and test renewal/CAA compatibility.
- [ ] Verify the deployment source is the private site repository or approved artifact, never public `site/` VNext source.
- [ ] Disable public source maps that expose private/proprietary source.
- [ ] Confirm no build-time or runtime secret is shipped to browser assets.
- [ ] Document rollback to the previous immutable artifact.

## Canonical identity and discovery

- [ ] Set one absolute canonical URL on every indexable page.
- [ ] Update GitHub repository homepage and reciprocal site link.
- [ ] Generate absolute Open Graph/Twitter image URLs and verify previews.
- [ ] Publish `sitemap.xml` and a matching `robots.txt`.
- [ ] Publish `/.well-known/security.txt` with contact, expiry, policy, preferred language, and canonical fields.
- [ ] Update Agent Skills/discovery URLs only after cold-install proof.
- [ ] Redirect retired GitHub Pages marketing URLs without breaking public historical documentation.

## Browser security

- [ ] Deploy a tested Content-Security-Policy; start report-only only while actively reviewing reports.
- [ ] Set `frame-ancestors`, `base-uri`, `object-src`, and `form-action` deliberately.
- [ ] Enable HSTS only after every required subdomain supports HTTPS; consider preload separately.
- [ ] Set `Referrer-Policy`, `Permissions-Policy`, and `X-Content-Type-Options`.
- [ ] Validate CORS, caching, redirects, error pages, and third-party script integrity/necessity.
- [ ] Confirm support/donation links cannot be changed by unauthenticated content or unsafe remote configuration.

## Support and donation integrity

- [ ] Verify every public receiving address and network out of band with the owner.
- [ ] Generate QR codes only from the verified public address and network label.
- [ ] Test copy buttons and network warnings on mobile and desktop.
- [ ] Publish provider links only; keep provider API/webhook/withdrawal secrets server-side.
- [ ] Record a reviewed change process for rotating addresses and warning users about phishing.

## Privacy-conscious analytics

- [ ] Decide whether analytics are needed; prefer no analytics until a question requires measurement.
- [ ] If used, minimize data, disable cross-site tracking/fingerprinting, shorten retention, and document lawful notice/consent requirements.
- [ ] Avoid recording source snippets, audit IDs, wallet interaction contents, or sensitive URL parameters.
- [ ] Test opt-out/consent behavior where applicable.

## Quality and launch proof

- [ ] Test 1440× and 1920× desktop plus 390× and 430× mobile.
- [ ] Test current Chrome/Chromium mobile and Safari/WebKit where available.
- [ ] Pass keyboard, focus, semantic structure, contrast, and reduced-motion checks.
- [ ] Record Lighthouse/performance evidence; resolve layout shift, hydration, console, and network errors.
- [ ] Verify all links, install snippets, forms, copy controls, metadata, redirects, 404, and offline/error states.
- [ ] Run secret/private-source leakage checks on the exact deploy artifact.
- [ ] Obtain operator approval for DNS cutover and publish a rollback owner/window.
