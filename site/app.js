const families = [
  ["Authentication","login, recovery, MFA, identity proofing"],
  ["Sessions","cookies, refresh, revocation, fixation, origin"],
  ["Authorization / BOLA / BFLA","roles, tenant, seller and object ownership"],
  ["Injection","SQL/PostgREST, command, template and stored input"],
  ["API Security","mass assignment, webhooks, RPCs and error paths"],
  ["Files / Uploads","type confusion, archives, parsers and storage"],
  ["SSRF / URL Fetching","redirects, metadata, internal networks and callbacks"],
  ["Browser / Client","XSS, CSP, CSRF, origin and client/server trust"],
  ["Business Logic","refunds, entitlement, workflow abuse and invariants"],
  ["Payments / Accounting","cost, payout, settlement, rounding and currency"],
  ["Race / Idempotency","retries, TOCTOU, exact-once and crash recovery"],
  ["Database / Migrations / RPC","constraints, triggers, RLS, drift and ordering"],
  ["Cryptography / Secrets","keys, tokens, hashing, rotation and leakage"],
  ["Supply Chain","dependencies, scripts, provenance and package confusion"],
  ["CI / CD","workflow permissions, artifacts, secrets and releases"],
  ["Cloud / Configuration","IAM, environment flags, exposure and unsafe defaults"],
  ["Privacy / Logging","PII, retention, exports, redaction and observability"],
  ["AI / Agent / MCP","tool authorization, poisoned context and agent identity"],
  ["Operational Security","admin tools, break-glass, monitoring and runbooks"],
  ["Release Security","build truth, migration gates, rollback and smoke"],
  ["Attack Surface Mapping","entrypoints, identities, assets and trust boundaries"]
];

const universal = `npx skills@latest add omarmohelal/SecHelix --skill sechelix`;
const installSnippets = {
  claude: `${universal}\n\n# then ask Claude:\n# Run a SecHelix audit on this authorized repository.`,
  codex: `${universal}\n\n# The repo also ships .codex/skills/sechelix/.`,
  glm: `# Run GLM inside a skills-capable coding host, then install SecHelix\n# through that host. Example with the open skills CLI:\n${universal}\n\n# The host supplies tools; GLM supplies the model.`,
  generic: `${universal}\n\n# Portable source of truth:\n# skills/sechelix/SKILL.md`
};

function renderCoverage(query = "") {
  const grid = document.querySelector("#coverageGrid");
  if (!grid) return;
  const q = query.trim().toLowerCase();
  const filtered = families.filter(([name, desc]) => `${name} ${desc}`.toLowerCase().includes(q));
  grid.innerHTML = filtered.map(([name, desc]) => `<article class="coverage-item"><strong>${name}</strong><span>${desc}</span></article>`).join("");
  const count = document.querySelector("#coverageCount");
  if (count) count.textContent = `${filtered.length} ${filtered.length === 1 ? "family" : "families"}`;
}

function setInstall(tab) {
  document.querySelectorAll(".tab").forEach((btn) => btn.classList.toggle("active", btn.dataset.tab === tab));
  const code = document.querySelector("#installCode code");
  if (code) code.textContent = installSnippets[tab] || installSnippets.generic;
}

function initReveal() {
  const els = [...document.querySelectorAll(".reveal")];
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) { els.forEach((el) => el.classList.add("visible")); return; }
  const io = new IntersectionObserver((entries) => entries.forEach((entry) => { if (entry.isIntersecting) { entry.target.classList.add("visible"); io.unobserve(entry.target); } }), { threshold: 0.12 });
  els.forEach((el) => io.observe(el));
}

function initTerminal() {
  const target = document.querySelector("#typeTarget");
  if (!target || matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  const phrases = ["verify --finding SHX-042", "gate report.json", "audit ./service --mode local"];
  let p = 0, i = 0, deleting = false;
  const tick = () => {
    const text = phrases[p]; target.textContent = text.slice(0, i);
    if (!deleting && i < text.length) i++; else if (!deleting) deleting = true; else if (i > 0) i--; else { deleting = false; p = (p + 1) % phrases.length; }
    setTimeout(tick, deleting ? 38 : i === text.length ? 900 : 62);
  };
  tick();
}

document.addEventListener("DOMContentLoaded", () => {
  renderCoverage(); setInstall("claude"); initReveal(); initTerminal();
  document.querySelector("#coverageSearch")?.addEventListener("input", (e) => renderCoverage(e.target.value));
  document.querySelectorAll(".tab").forEach((btn) => btn.addEventListener("click", () => setInstall(btn.dataset.tab)));
  document.querySelector("#copyInstall")?.addEventListener("click", async (e) => {
    const text = document.querySelector("#installCode code")?.textContent || "";
    try { await navigator.clipboard.writeText(text); e.currentTarget.textContent = "Copied"; setTimeout(() => e.currentTarget.textContent = "Copy", 1200); }
    catch { e.currentTarget.textContent = "Select & copy"; }
  });
});