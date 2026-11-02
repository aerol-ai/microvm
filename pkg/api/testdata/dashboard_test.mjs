// Tests for the dashboard's sign-in logic (plans/identity-and-access.md
// §5.7, task T8). TestDashboardPageLogic in pkg/api/dashboard_test.go
// extracts the page's inline script, then runs:
//
//   DASHBOARD_SCRIPT=<extracted script> node --test pkg/api/testdata/dashboard_test.mjs
//
// The script runs in this realm with __AEROLVM_TEST__ set, so it does not
// boot; it hands its DOM-free functions over as globalThis.__dashboard. No
// browser, no network: every fetch, storage and GIS object below is a fake.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) { globalThis.crypto = webcrypto; }
globalThis.__AEROLVM_TEST__ = true;
vm.runInThisContext(readFileSync(process.env.DASHBOARD_SCRIPT, "utf8"), { filename: "dashboard-inline.js" });
const D = globalThis.__dashboard;
assert.ok(D, "the page script did not expose its functions under __AEROLVM_TEST__");

// The §5.5 identity file as discovery publishes it, plus the two workload
// issuers (no client ids) and a CLI-only issuer, to prove the page filters
// on its own and not only because T6 already did.
const EXAMPLE = {
  version: 1,
  identity_enabled: true,
  ui_url: "https://api.acme.dev/ui",
  issuers: [
    { name: "okta", display_name: "Acme Okta", kind: "oidc", url: "https://acme.okta.com/oauth2/default", clients: { cli: "0oa1cli", dashboard: "0oa1dash" } },
    { name: "google", display_name: "Google", kind: "google", url: "https://accounts.google.com", clients: { cli: "123-cli.apps.googleusercontent.com", dashboard: "123-dash.apps.googleusercontent.com" } },
    { name: "github-actions", display_name: "github-actions", kind: "oidc", url: "https://token.actions.githubusercontent.com", clients: {} },
    { name: "eks-prod", display_name: "eks-prod", kind: "oidc", url: "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE", clients: {} },
    { name: "cli-only", display_name: "CLI only", kind: "oidc", url: "https://cli.example.com", clients: { cli: "c1" } },
  ],
};

const loc = (u) => new URL(u);
const HTTPS = loc("https://api.acme.dev/ui");
const PLAIN = loc("http://10.0.0.5:21212/ui");
const TUNNEL = loc("http://localhost:21212/ui");

function only(discovery, ...names) {
  return Object.assign({}, discovery, { issuers: discovery.issuers.filter((i) => names.includes(i.name)) });
}

function fakeStorage() {
  const m = new Map();
  return {
    m,
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => { m.set(k, String(v)); },
    removeItem: (k) => { m.delete(k); },
  };
}

function fakeGoogle() {
  const calls = [];
  return {
    calls,
    accounts: { id: { disableAutoSelect: () => calls.push("disableAutoSelect"), prompt: () => calls.push("prompt") } },
  };
}

function response(status, body) {
  return { status, ok: status >= 200 && status < 300, json: async () => body, text: async () => JSON.stringify(body) };
}

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

const tick = () => new Promise((r) => setTimeout(r, 0));
async function flush(n = 10) { for (let i = 0; i < n; i += 1) { await tick(); } }

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function jwt(claims) { return b64url({ alg: "RS256", kid: "k1" }) + "." + b64url(claims) + ".c2ln"; }

// ---------- DR9 wording, DR4 line ----------

test("state wording matches the design review's DR9 table word for word", () => {
  const want = {
    loading: "Loading sign-in options…",
    discoveryFailed: "Couldn't load sign-in options. You can still use an API token.",
    signingIn: "Signing you in…",
    staleAttempt: "That sign-in attempt expired. Please try again.",
    popupBlocked: "Your browser blocked the Google sign-in window. Allow pop-ups for this site, then try again.",
    clockSkew: "Your computer's clock is more than a minute off. Fix the clock, then sign in again.",
    unavailable: "Sign-in is unavailable on this server right now. Try again in a minute, or use an API token.",
    pointerTunnel: "SSO sign-in needs a secure connection. Reach this page through an SSH tunnel to localhost:21212.",
    plainHTTP: "This connection isn't encrypted. Your token will cross the network in plain text.",
    patRejected: "Invalid or expired token. Sign in again.",
    tokenExpired: "That token has expired.",
    tokenInvalid: "That token isn't valid or was revoked.",
    lineCompany: "Sign in with your company account.",
    lineToken: "Sign in with an API token.",
    signedOut: "Signed out.",
    expired: "Your sign-in expired.",
    operatorTitle: "Actions are recorded as the server, not a person.",
    noAccessHeading: "You're signed in, but you don't have access here.",
    noAccessGuidance: "No access rule on this server matches your account. Ask your AerolVM admin to add one for a group you're in.",
    noGroups: "Your sign-in carried no groups.",
    overage: "Your sign-in carried too many groups to list. Ask your admin to bind an Entra app role instead.",
    consoleNeedsAdmin: "This console shows fleet health and needs the admin role.",
  };
  for (const [k, v] of Object.entries(want)) { assert.equal(D.MSG[k], v, k); }
  assert.equal(D.MSG.pointerOpen + "https://api.acme.dev/ui", "SSO sign-in needs a secure connection. Open https://api.acme.dev/ui");
  assert.equal(D.msgOpening("Acme Okta"), "Opening Acme Okta…");
  assert.equal(D.msgProviderError("Acme Okta", "access_denied"), "Acme Okta didn't sign you in (access_denied). Try again, or use a different account.");
  assert.equal(D.msgWrongApp("wrong_audience"), "This server doesn't accept sign-ins from that app (wrong_audience). Ask your AerolVM admin to check the dashboard client id.");
  assert.equal(D.msgUnverified("invalid_signature"), "That sign-in couldn't be verified (invalid_signature). Try again. If it keeps failing, tell your AerolVM admin.");
});

test("401 wording per credential kind and D17 reason; the PAT text is unchanged (L8)", () => {
  const cases = [
    ["pat", "", "Invalid or expired token. Sign in again."],
    ["jwt", "", "Invalid or expired token. Sign in again."],
    ["avm", "expired", "That token has expired."],
    ["avm", "unknown_or_revoked", "That token isn't valid or was revoked."],
    ["avm", "malformed", "That token isn't valid or was revoked."],
    ["sso", "expired", "Your sign-in expired."],
    ["jwt", "expired", "That token has expired."],
    ["sso", "not_yet_valid", D.MSG.clockSkew],
    ["sso", "wrong_audience", D.msgWrongApp("wrong_audience")],
    ["sso", "unknown_issuer", D.msgWrongApp("unknown_issuer")],
    ["sso", "too_long_lived", D.msgWrongApp("too_long_lived")],
    ["sso", "invalid_signature", D.msgUnverified("invalid_signature")],
    ["sso", "malformed", D.msgUnverified("malformed")],
    ["jwt", "unknown_or_revoked", D.msgUnverified("unknown_or_revoked")],
  ];
  for (const [kind, reason, want] of cases) { assert.equal(D.rejectionMessage(kind, reason), want, kind + "/" + reason); }
});

test("credential kinds", () => {
  assert.equal(D.credentialKind("pat-token", null), "pat");
  assert.equal(D.credentialKind("avm_abc123", null), "avm");
  assert.equal(D.credentialKind(jwt({ sub: "x" }), null), "jwt");
  assert.equal(D.credentialKind(jwt({ sub: "x" }), { issuer: "okta" }), "sso");
});

// ---------- DR3, DR4, D18: the sign-in box ----------

test("the §5.5 example file renders exactly two buttons, none for workload issuers (DR3)", () => {
  const m = D.signInModel({ phase: "ready", discovery: EXAMPLE, location: HTTPS, lastIssuer: "" });
  assert.deepEqual(m.buttons.map((b) => b.label), ["Sign in with Acme Okta", "Sign in with Google"]);
  assert.deepEqual(m.buttons.map((b) => b.kind), ["oidc", "google"]);
  assert.deepEqual(m.buttons.map((b) => b.client), ["0oa1dash", "123-dash.apps.googleusercontent.com"]);
  assert.equal(m.line, "Sign in with your company account.");
  assert.equal(m.tokenOpen, false, "the token disclosure is closed when SSO buttons show (DR4)");
  assert.equal(m.divider, true);
  assert.equal(m.pointer, null);
  assert.equal(m.plainHTTPWarning, false);
  assert.equal(m.host, "api.acme.dev");
});

test("a missing display_name falls back to the issuer name", () => {
  const d = { identity_enabled: true, issuers: [{ name: "keycloak", url: "https://kc.acme.dev/realms/acme", clients: { dashboard: "dash" } }] };
  assert.deepEqual(D.dashboardIssuers(d).map((b) => b.label), ["Sign in with keycloak"]);
});

test("no buttons when identity is off, no issuer has a dashboard client, or an issuer URL is not https", () => {
  const off = Object.assign({}, EXAMPLE, { identity_enabled: false });
  const cases = [
    ["identity off", off],
    ["workload and CLI issuers only", only(EXAMPLE, "github-actions", "eks-prod", "cli-only")],
    ["http issuer URL", { identity_enabled: true, issuers: [{ name: "x", url: "http://idp.local", clients: { dashboard: "d" } }] }],
    ["no issuers field", { identity_enabled: true }],
  ];
  for (const [name, discovery] of cases) {
    const m = D.signInModel({ phase: "ready", discovery, location: HTTPS, lastIssuer: "" });
    assert.equal(m.buttons.length, 0, name);
    assert.equal(m.tokenOpen, true, name + ": the token box is open and the only content (DR4)");
    assert.equal(m.divider, false, name);
    assert.equal(m.line, "Sign in with an API token.", name);
    assert.equal(D.focusTarget(m), "token", name);
  }
});

test("buttons are hidden on non-local plain HTTP; the page points at ui_url (D18, DR9)", () => {
  const m = D.signInModel({ phase: "ready", discovery: EXAMPLE, location: PLAIN, lastIssuer: "" });
  assert.equal(m.buttons.length, 0);
  assert.deepEqual(m.pointer, { text: "SSO sign-in needs a secure connection. Open ", href: "https://api.acme.dev/ui" });
  assert.equal(m.tokenOpen, true);
  assert.equal(m.plainHTTPWarning, true);
  assert.equal(m.line, "Sign in with an API token.");

  const noDomain = Object.assign({}, EXAMPLE, { ui_url: undefined });
  const m2 = D.signInModel({ phase: "ready", discovery: noDomain, location: PLAIN, lastIssuer: "" });
  assert.deepEqual(m2.pointer, { text: D.MSG.pointerTunnel, href: "" });

  const httpUI = Object.assign({}, EXAMPLE, { ui_url: "http://api.acme.dev/ui" });
  assert.deepEqual(D.signInModel({ phase: "ready", discovery: httpUI, location: PLAIN }).pointer.href, "", "only an https ui_url is linked");

  const tunnel = D.signInModel({ phase: "ready", discovery: EXAMPLE, location: TUNNEL, lastIssuer: "" });
  assert.equal(tunnel.buttons.length, 2, "an SSH tunnel to localhost signs in");
  assert.equal(tunnel.plainHTTPWarning, false);

  const offPlain = D.signInModel({ phase: "ready", discovery: { identity_enabled: false, issuers: [] }, location: PLAIN });
  assert.equal(offPlain.pointer, null, "identity off: no pointer, just the token box");
  assert.equal(offPlain.plainHTTPWarning, true, "the token box warns on plain HTTP");
});

test("secure origins", () => {
  const cases = [
    ["https://api.acme.dev/ui", true],
    ["https://10.0.0.5:8443/ui", true],
    ["http://localhost:21212/ui", true],
    ["http://127.0.0.1:21212/ui", true],
    ["http://[::1]:21212/ui", true],
    ["http://dash.localhost:21212/ui", true],
    ["http://10.0.0.5:21212/ui", false],
    ["http://api.acme.dev/ui", false],
  ];
  for (const [u, want] of cases) { assert.equal(D.ssoAllowed(loc(u)), want, u); }
});

test("loading and failed discovery states (Pass 2 table)", () => {
  const loading = D.signInModel({ phase: "loading", discovery: null, location: HTTPS });
  assert.equal(loading.loading, true);
  assert.equal(loading.buttons.length, 0);
  assert.equal(loading.tokenOpen, false);
  assert.equal(D.focusTarget(loading), "summary");

  const failed = D.signInModel({ phase: "failed", discovery: null, location: HTTPS });
  assert.equal(failed.message, "Couldn't load sign-in options. You can still use an API token.");
  assert.equal(failed.retry, true);
  assert.equal(failed.tokenOpen, true, "the token disclosure opens");
  assert.equal(failed.line, "Sign in with an API token.");
});

test("'Use a different account' targets the only issuer, or the one this tab last used (DR7)", () => {
  const two = D.signInModel({ phase: "ready", discovery: EXAMPLE, location: HTTPS, lastIssuer: "" });
  assert.equal(two.switchIssuer, "", "several issuers and no earlier sign-in: nothing to switch from");
  assert.equal(D.signInModel({ phase: "ready", discovery: EXAMPLE, location: HTTPS, lastIssuer: "google" }).switchIssuer, "google");
  assert.equal(D.signInModel({ phase: "ready", discovery: EXAMPLE, location: HTTPS, lastIssuer: "gone" }).switchIssuer, "");
  assert.equal(D.signInModel({ phase: "ready", discovery: only(EXAMPLE, "okta"), location: HTTPS }).switchIssuer, "okta");
});

// ---------- DR13: keyboard focus ----------

test("focus starts on the first element that isn't Google's frame (DR13)", () => {
  const googleFirst = { identity_enabled: true, issuers: [EXAMPLE.issuers[1], EXAMPLE.issuers[0]] };
  const m1 = D.signInModel({ phase: "ready", discovery: googleFirst, location: HTTPS });
  assert.equal(D.focusTarget(m1), "sso:okta", "Okta when Google is listed first");

  const m2 = D.signInModel({ phase: "ready", discovery: only(EXAMPLE, "google"), location: HTTPS });
  assert.equal(D.focusTarget(m2), "switch", "'Use a different account' when Google is the only issuer");

  const m3 = D.signInModel({ phase: "ready", discovery: EXAMPLE, location: HTTPS });
  assert.equal(D.focusTarget(m3), "sso:okta");

  const m4 = { buttons: [{ name: "google", kind: "google" }], switchIssuer: "", tokenOpen: false };
  assert.equal(D.focusTarget(m4), "summary", "else the token disclosure's summary");
});

// ---------- DR11, DR12: Google's button ----------

test("Google's button uses the DR11 options at the box's measured width (DR12)", () => {
  assert.deepEqual(JSON.parse(JSON.stringify(D.gisButtonOptions(312))), {
    type: "standard", theme: "filled_black", size: "large", shape: "rectangular",
    text: "signin_with", logo_alignment: "left", width: 312,
  });
  // 320 px viewport: the box is 92vw = 294.4 px with 16 px padding → 262.
  assert.equal(D.gisWidth(262.4), 262);
  assert.equal(D.gisWidth(150), 200, "GIS refuses less than 200 px");
  assert.equal(D.gisWidth(512), 400, "GIS refuses more than 400 px");
  assert.equal(D.gisWidth(undefined), 200);
});

// ---------- DR1, DR5, DR10: who you are ----------

test("only admin and operator callers get the overview (DR1)", () => {
  const p = (kind, role, extra) => Object.assign({ principal: { kind, id: kind + ":x", name: "x" }, role }, extra || {});
  const cases = [
    [p("operator", "admin", { team: "*" }), "overview"],
    [p("node", "admin"), "overview"],
    [p("oidc", "admin", { team: "*" }), "overview"],
    [p("token", "admin", { team: "*" }), "overview"],
    [p("oidc", "viewer", { team: "payments" }), "signedin"],
    [p("oidc", "runner", { team: "*" }), "signedin"],
    [p("oidc", "auditor", { team: "*" }), "signedin"],
    [p("token", "viewer", { team: "*" }), "signedin"],
    [p("controlplane", "runner"), "signedin"],
    [null, "signedin"],
  ];
  for (const [who, want] of cases) { assert.equal(D.routeFor(who), want, JSON.stringify(who)); }
});

test("the signed-in screen names role, team and a two-line CLI pointer for this host (DR1, DR10)", () => {
  const who = { principal: { kind: "oidc", id: "oidc:okta:00u1", name: "alice@acme.com" }, role: "viewer", team: "payments" };
  const m = D.signedInModel(who, "https://api.acme.dev");
  assert.equal(m.name, "alice@acme.com");
  assert.equal(m.roleLine, "Role viewer · team payments");
  assert.equal(m.cli, "aerolvm login https://api.acme.dev\naerolvm list");
  assert.equal(D.signedInModel(Object.assign({}, who, { team: "*" }), "https://h").roleLine, "Role viewer · all teams");
  assert.equal(D.signedInModel({ principal: { kind: "controlplane", id: "controlplane:u1" }, role: "runner" }, "https://h").roleLine, "Role runner");
  assert.equal(D.signedInModel({ principal: { kind: "token", id: "tok_1" }, role: "runner", team: "x" }, "https://h").name, "tok_1");
});

test("header identity: name and admin pill, or 'Server token' with an operator pill warned only with identity on (DR5)", () => {
  const admin = { principal: { kind: "oidc", id: "oidc:okta:00u1", name: "alice@acme.com" }, role: "admin", team: "*" };
  assert.deepEqual(JSON.parse(JSON.stringify(D.headerIdentity(admin, true))), { name: "alice@acme.com", title: "alice@acme.com", pill: "admin", pillClass: "muted", pillTitle: "" });
  const pat = { principal: { kind: "operator", id: "operator" }, role: "admin", team: "*" };
  assert.deepEqual(JSON.parse(JSON.stringify(D.headerIdentity(pat, true))), {
    name: "Server token", title: "Server token", pill: "operator", pillClass: "warn",
    pillTitle: "Actions are recorded as the server, not a person.",
  });
  const off = D.headerIdentity(pat, false);
  assert.equal(off.pillClass, "muted", "identity off: the pill stays muted (L8)");
  assert.equal(off.pillTitle, "");
  assert.equal(D.headerIdentity({ principal: { kind: "token", id: "tok_9" }, role: "admin" }, true).name, "tok_9");
});

// ---------- DR8: the no-access screen ----------

test("the no-access screen renders from the 403's own fields (DR8)", () => {
  const groups = Array.from({ length: 12 }, (_, i) => "g" + i);
  const body = { error: "no role binding", reason: "no_binding", issuer: "okta", name: "alice@acme.com", groups };
  const m = D.noAccessModel(body, EXAMPLE);
  assert.equal(m.heading, "You're signed in, but you don't have access here.");
  assert.equal(m.who, "alice@acme.com · Acme Okta", "the issuer's display name, not its slug");
  assert.equal(m.guidance, D.MSG.noAccessGuidance);
  assert.equal(m.groupsSummary, "Groups your sign-in carried (12)");
  assert.equal(m.groupsShown.length, 12);
  assert.equal(m.groupsMore, "");
  assert.equal(m.noGroups, false);
  assert.equal(m.overage, false);
  assert.equal(m.switchIssuer, "okta");
  assert.ok(D.isNoBinding(403, body));
  assert.ok(!D.isNoBinding(403, { error: "forbidden" }));
  assert.ok(!D.isNoBinding(401, body));
  assert.ok(!D.isNoBinding(403, null));
});

test("the group list stops at 50, then 'and N more'", () => {
  const groups = Array.from({ length: 63 }, (_, i) => "group-" + i);
  const m = D.noAccessModel({ reason: "no_binding", issuer: "okta", name: "a", groups }, EXAMPLE);
  assert.equal(m.groupsSummary, "Groups your sign-in carried (63)");
  assert.equal(m.groupsShown.length, 50);
  assert.equal(m.groupsShown[49], "group-49");
  assert.equal(m.groupsMore, "and 13 more");
});

test("no groups, and the Entra overage, have their own wording and no list", () => {
  const none = D.noAccessModel({ reason: "no_binding", issuer: "okta", name: "a" }, EXAMPLE);
  assert.equal(none.noGroups, true);
  assert.equal(none.groupsSummary, "");

  const over = D.noAccessModel({ reason: "group_overage", issuer: "entra", name: "b@acme.com", groups: ["ignored"] }, EXAMPLE);
  assert.equal(over.overage, true);
  assert.equal(over.noGroups, false);
  assert.equal(over.groupsSummary, "");
  assert.equal(over.groupsShown.length, 0);
  assert.equal(over.who, "b@acme.com · entra", "an issuer discovery doesn't list falls back to its name");
  assert.equal(over.switchIssuer, "", "no dashboard client: nothing to switch to");

  const cliOnly = D.noAccessModel({ reason: "no_binding", issuer: "cli-only", name: "c" }, EXAMPLE);
  assert.equal(cliOnly.who, "c · CLI only");
  assert.equal(cliOnly.switchIssuer, "");
});

// ---------- token handling: nonce, aud, expiry ----------

test("an ID token is tied to this attempt: nonce, aud and exp", () => {
  const now = 1_800_000_000;
  const want = { nonce: "n-1", clientId: "0oa1dash", nowSec: now };
  const ok = { nonce: "n-1", aud: "0oa1dash", exp: now + 3600, sub: "00u1" };
  const cases = [
    [ok, ""],
    [Object.assign({}, ok, { aud: ["other", "0oa1dash"] }), ""],
    [Object.assign({}, ok, { nonce: "n-2" }), "nonce_mismatch"],
    [Object.assign({}, ok, { nonce: undefined }), "nonce_mismatch"],
    [Object.assign({}, ok, { aud: "0oa1cli" }), "wrong_audience"],
    [Object.assign({}, ok, { aud: ["a", "b"] }), "wrong_audience"],
    [Object.assign({}, ok, { exp: now }), "expired"],
    [Object.assign({}, ok, { exp: "soon" }), "expired"],
    [null, "malformed"],
  ];
  for (const [claims, problem] of cases) { assert.equal(D.checkIDToken(claims, want), problem, JSON.stringify(claims)); }
  assert.equal(D.checkIDToken(ok, Object.assign({}, want, { nonce: "" })), "nonce_mismatch", "no nonce of our own: refuse");
  assert.equal(D.idTokenProblemMessage("nonce_mismatch"), "That sign-in attempt expired. Please try again.");
  assert.equal(D.idTokenProblemMessage("wrong_audience"), D.msgWrongApp("wrong_audience"));
  assert.equal(D.idTokenProblemMessage("expired"), D.MSG.clockSkew);
  assert.equal(D.idTokenProblemMessage("malformed"), D.msgUnverified("malformed"));
});

test("decodeJWT reads UTF-8 claims and refuses anything else", () => {
  assert.equal(D.decodeJWT(jwt({ name: "Zoë Ångström", sub: "1" })).name, "Zoë Ångström");
  for (const bad of ["", "a.b", "a.b.c.d", "x.!!!.y", "a." + b64url([1, 2]) + ".c", "a." + Buffer.from("not json").toString("base64url") + ".c", null]) {
    assert.equal(D.decodeJWT(bad), null, String(bad));
  }
});

test("PKCE: the RFC 7636 appendix B vector, and random values are url-safe", async () => {
  assert.equal(await D.pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  const a = D.randomToken(32);
  assert.match(a, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(a, D.randomToken(32));
  assert.equal(D.b64urlDecodeText(D.b64urlEncode(new TextEncoder().encode("héllo"))), "héllo");
});

// ---------- DR7: prompts and the authorization request ----------

test("prompt choice: none to renew, select_account or login to switch, nothing to sign in (DR6, DR7)", () => {
  assert.equal(D.promptFor("renew", ["none", "login"]), "none");
  assert.equal(D.promptFor("switch", ["none", "login", "consent", "select_account"]), "select_account");
  assert.equal(D.promptFor("switch", ["none", "login"]), "login");
  assert.equal(D.promptFor("switch", undefined), "login", "a provider that doesn't publish the list");
  assert.equal(D.promptFor("interactive", ["select_account"]), "");
});

test("the authorization request is a PKCE public-client code flow back to /ui", () => {
  const u = new URL(D.authorizeURL("https://acme.okta.com/oauth2/default/v1/authorize?tenant=a", {
    clientId: "0oa1dash", redirectUri: D.redirectURI(HTTPS), state: "st", nonce: "nn", challenge: "ch", prompt: "select_account",
  }));
  const q = u.searchParams;
  assert.equal(u.origin + u.pathname, "https://acme.okta.com/oauth2/default/v1/authorize");
  assert.equal(q.get("tenant"), "a", "the provider's own query survives");
  assert.equal(q.get("response_type"), "code");
  assert.equal(q.get("client_id"), "0oa1dash");
  assert.equal(q.get("redirect_uri"), "https://api.acme.dev/ui");
  assert.equal(q.get("scope"), "openid email profile");
  assert.equal(q.get("state"), "st");
  assert.equal(q.get("nonce"), "nn");
  assert.equal(q.get("code_challenge"), "ch");
  assert.equal(q.get("code_challenge_method"), "S256");
  assert.equal(q.get("prompt"), "select_account");
  assert.equal(q.has("client_secret"), false);
  const plain = new URL(D.authorizeURL("https://idp/authorize", { clientId: "c", redirectUri: "r", state: "s", nonce: "n", challenge: "c", prompt: "" }));
  assert.equal(plain.searchParams.has("prompt"), false);
  assert.equal(D.redirectURI(TUNNEL), "http://localhost:21212/ui");
});

test("groups is asked for only where the provider makes it a scope, as Dex does", () => {
  const scopeFor = (scopesSupported) => new URL(D.authorizeURL("https://idp/authorize", {
    clientId: "c", redirectUri: "r", state: "s", nonce: "n", challenge: "c", prompt: "", scopesSupported,
  })).searchParams.get("scope");
  assert.equal(scopeFor(["openid", "email", "groups", "profile", "offline_access"]), "openid email profile groups");
  assert.equal(scopeFor(["openid", "email", "profile", "offline_access"]), "openid email profile",
    "no groups scope, and never offline_access: the browser keeps only the ID token");
  assert.equal(scopeFor([]), "openid email profile");
  assert.equal(scopeFor(undefined), "openid email profile", "a provider that doesn't publish the list");
});

test("the provider's discovery document gives the endpoints and prompt values", async () => {
  const seen = [];
  const fetchOK = async (u) => {
    seen.push(u);
    return response(200, {
      authorization_endpoint: "https://acme.okta.com/oauth2/default/v1/authorize",
      token_endpoint: "https://acme.okta.com/oauth2/default/v1/token",
      prompt_values_supported: ["none", "login", "select_account"],
      scopes_supported: ["openid", "email", "profile", "groups"],
    });
  };
  const meta = await D.providerMetadata(fetchOK, "https://acme.okta.com/oauth2/default/");
  assert.deepEqual(seen, ["https://acme.okta.com/oauth2/default/.well-known/openid-configuration"]);
  assert.equal(meta.token_endpoint, "https://acme.okta.com/oauth2/default/v1/token");
  assert.deepEqual([...meta.prompt_values_supported], ["none", "login", "select_account"]);
  assert.deepEqual([...meta.scopes_supported], ["openid", "email", "profile", "groups"]);

  const noPrompts = await D.providerMetadata(async () => response(200, { authorization_endpoint: "https://e/a", token_endpoint: "https://e/t" }), "https://e");
  assert.equal(noPrompts.prompt_values_supported.length, 0);
  assert.equal(noPrompts.scopes_supported.length, 0);
  const badScopes = await D.providerMetadata(async () => response(200, { authorization_endpoint: "https://e/a", token_endpoint: "https://e/t", scopes_supported: "groups" }), "https://e");
  assert.equal(badScopes.scopes_supported.length, 0, "a scopes_supported that isn't a list is ignored");
  await assert.rejects(D.providerMetadata(async () => response(200, { authorization_endpoint: "http://e/a", token_endpoint: "https://e/t" }), "https://e"));
  await assert.rejects(D.providerMetadata(async () => response(404, {}), "https://e"));
});

test("the code is redeemed with the verifier and only the ID token is kept", async () => {
  const pending = { client: "0oa1dash", verifier: "ver", tokenEndpoint: "https://acme.okta.com/v1/token" };
  let sent = null;
  const ok = await D.exchangeCode(async (u, o) => { sent = { u, o }; return response(200, { id_token: "id.tok.en", access_token: "a", refresh_token: "r" }); }, pending, "code-1", "https://api.acme.dev/ui");
  assert.deepEqual(JSON.parse(JSON.stringify(ok)), { idToken: "id.tok.en" });
  assert.equal(sent.u, "https://acme.okta.com/v1/token");
  assert.equal(sent.o.method, "POST");
  const form = new URLSearchParams(sent.o.body);
  assert.equal(form.get("grant_type"), "authorization_code");
  assert.equal(form.get("code"), "code-1");
  assert.equal(form.get("code_verifier"), "ver");
  assert.equal(form.get("client_id"), "0oa1dash");
  assert.equal(form.get("redirect_uri"), "https://api.acme.dev/ui");
  assert.equal(form.has("client_secret"), false, "no client secret anywhere (§5.7)");

  assert.equal((await D.exchangeCode(async () => response(400, { error: "invalid_grant" }), pending, "c", "r")).error, "invalid_grant");
  assert.equal((await D.exchangeCode(async () => response(400, { error: "<script>" }), pending, "c", "r")).error, "unknown_error");
  assert.equal((await D.exchangeCode(async () => { throw new Error("blocked by CSP"); }, pending, "c", "r")).error, "network_error");
  assert.equal((await D.exchangeCode(async () => ({ status: 200, ok: true, json: async () => { throw new Error("html"); } }), pending, "c", "r")).error, "token_error");
});

test("the return from the provider must match this tab's attempt", () => {
  assert.equal(D.callbackParams("?foo=1"), null);
  assert.deepEqual(JSON.parse(JSON.stringify(D.callbackParams("?code=c1&state=s1"))), { code: "c1", error: "", state: "s1" });
  assert.deepEqual(JSON.parse(JSON.stringify(D.callbackParams("?error=access_denied&state=s1"))), { code: "", error: "access_denied", state: "s1" });
  const now = 1_800_000_000_000;
  const pending = { state: "s1", at: now - 1000 };
  assert.equal(D.pendingProblem(pending, "s1", now), "");
  assert.equal(D.pendingProblem(null, "s1", now), "stale");
  assert.equal(D.pendingProblem(pending, "s2", now), "stale");
  assert.equal(D.pendingProblem(pending, "", now), "stale");
  assert.equal(D.pendingProblem({ state: "s1", at: now - 11 * 60 * 1000 }, "s1", now), "stale");
  assert.equal(D.pendingProblem({ state: "s1" }, "s1", now), "stale");
  assert.equal(D.safeCode("access_denied"), "access_denied");
  assert.equal(D.safeCode("a b"), "unknown_error");
  assert.equal(D.safeCode(""), "unknown_error");
});

test("the SSO session record carries what a renewal needs", () => {
  const issuer = { name: "okta", display: "Acme Okta", kind: "oidc", url: "https://acme.okta.com", client: "0oa1dash" };
  const meta = D.ssoMetaFor(issuer, { exp: 123, sub: "00u1" });
  assert.deepEqual(JSON.parse(JSON.stringify(meta)), { issuer: "okta", display: "Acme Okta", kind: "oidc", url: "https://acme.okta.com", client: "0oa1dash", exp: 123, sub: "00u1", route: "" });
  assert.deepEqual(JSON.parse(JSON.stringify(D.issuerFromMeta(meta))), issuer);
});

// ---------- DR6: renewal ----------

function renewalHarness(opts) {
  opts = opts || {};
  const tracker = D.createTracker();
  const log = { beginRedirect: [], navigate: [], saveView: 0, failed: 0, failedReasons: [], expired: 0, renewed: 0, rejected: [], fetches: [] };
  let bearer = "old-token";
  const session = opts.session || { issuer: "okta", display: "Acme Okta", kind: "oidc", url: "https://acme.okta.com", client: "0oa1dash", exp: 1 };
  const renewal = D.createSingleFlight(D.createRenewer({
    session: () => session,
    recentlyRenewed: () => !!opts.recentlyRenewed,
    googleRenew: opts.googleRenew || (async () => false),
    idle: () => tracker.idle(),
    beginRedirect: opts.beginRedirect || (async (issuer, mode) => { log.beginRedirect.push([issuer.name, mode]); return "https://acme.okta.com/authorize?prompt=none"; }),
    saveView: () => { log.saveView += 1; },
    navigate: (u) => { log.navigate.push(u); },
    onFailed: (reason) => { log.failed += 1; log.failedReasons.push(reason); },
    onRenewed: () => { log.renewed += 1; },
  }));
  let expired = false;
  const api = D.createAPI({
    fetch: async (path, o) => { log.fetches.push([path, o.headers.Authorization]); return opts.fetch(path, o); },
    bearer: () => bearer,
    kind: () => opts.kind || "sso",
    renewal,
    tracker,
    isExpired: () => expired,
    onExpired: () => { log.expired += 1; },
    onRejected: (kind, reason) => { log.rejected.push([kind, reason]); },
  });
  return { api, renewal, tracker, log, setBearer: (b) => { bearer = b; }, setExpired: (e) => { expired = e; } };
}

const expired401 = () => response(401, { error: "unauthorized", reason: "expired" });

test("four simultaneous 401 expired responses start exactly one renewal", async () => {
  const gates = [deferred(), deferred(), deferred(), deferred()];
  let i = 0;
  const h = renewalHarness({ fetch: () => gates[i++].promise });
  const calls = ["/health", "/v1/cluster/leader", "/v1/cluster/members", "/v1/metrics"].map((p) => h.api(p));
  calls.forEach((c) => c.catch(() => {}));
  await flush();
  assert.equal(h.tracker.count(), 4, "all four panels are in flight");
  gates.forEach((g) => g.resolve(expired401()));
  await flush();
  assert.equal(h.log.beginRedirect.length, 1, "one renewal, not four");
  assert.deepEqual(h.log.beginRedirect[0], ["okta", "renew"]);
  assert.equal(h.log.navigate.length, 1);
  assert.equal(h.log.saveView, 1, "the view is saved before leaving");
  assert.equal(h.log.rejected.length, 0, "an expiry is not a rejection");
  assert.equal(h.renewal.active(), true, "the page is leaving; the renewal never settles");

  // A request made while the renewal runs waits instead of sending the
  // expiring token.
  h.api("/v1/cluster/sandbox-index").catch(() => {});
  await flush();
  assert.equal(h.log.fetches.length, 4);
});

test("at exp − 120 s an SPA issuer gets a prompt=none redirect, after in-flight requests finish", async () => {
  assert.equal(D.RENEW_BEFORE_S, 120);
  const now = 1_800_000_000_000;
  assert.equal(D.renewDelayMs(now / 1000 + 3600, now), 3480 * 1000);
  assert.equal(D.renewDelayMs(now / 1000 + 60, now), 0, "already inside the window: renew now");
  assert.equal(D.renewDelayMs(now / 1000 - 10, now), 0);

  const gate = deferred();
  const h = renewalHarness({ fetch: () => gate.promise });
  const inflight = h.api("/v1/cluster/nodes/n1/drain", { method: "POST" });
  await flush();
  h.renewal.run("proactive");
  await flush();
  assert.equal(h.log.navigate.length, 0, "the redirect waits for the in-flight request");
  assert.equal(h.log.saveView, 0);
  gate.resolve(response(200, { ok: true }));
  assert.equal((await inflight).status, 200);
  await flush();
  assert.equal(h.log.navigate.length, 1);
  assert.equal(h.log.navigate[0], "https://acme.okta.com/authorize?prompt=none");
  assert.equal(h.log.saveView, 1);
});

test("Google renews in place through GIS and the refused request is retried with the new token", async () => {
  let n = 0;
  let h;
  h = renewalHarness({
    session: { issuer: "google", kind: "google", client: "123-dash", url: "https://accounts.google.com", display: "Google" },
    googleRenew: async () => { h.setBearer("new-token"); return true; },
    fetch: () => (n++ === 0 ? expired401() : response(200, { ok: true })),
  });
  const res = await h.api("/v1/cluster/leader");
  assert.equal(res.status, 200);
  assert.deepEqual(h.log.fetches.map((f) => f[1]), ["Bearer old-token", "Bearer new-token"]);
  assert.equal(h.log.renewed, 1);
  assert.equal(h.log.navigate.length, 0, "no reload for Google");
});

test("a failed renewal shows the banner once and keeps the view; later calls send nothing", async () => {
  const h = renewalHarness({
    session: { issuer: "google", kind: "google", client: "c", url: "https://accounts.google.com", display: "Google" },
    googleRenew: async () => false,
    fetch: () => expired401(),
  });
  await assert.rejects(h.api("/health"), (err) => err instanceof D.SessionExpired && err.message === "Your sign-in expired.");
  assert.equal(h.log.failed, 1);
  h.setExpired(true);
  await assert.rejects(h.api("/health"), D.SessionExpired);
  assert.equal(h.log.fetches.length, 1, "nothing is sent once the sign-in expired");

  const again = renewalHarness({ fetch: () => expired401(), recentlyRenewed: true });
  await assert.rejects(again.api("/health"), D.SessionExpired);
  assert.equal(again.log.failed, 1, "a renewal that just came back doesn't redirect again");
  assert.equal(again.log.navigate.length, 0);

  const unreachable = renewalHarness({ fetch: () => expired401(), beginRedirect: async () => { throw new Error("down"); } });
  await assert.rejects(unreachable.api("/health"), D.SessionExpired);
  assert.equal(unreachable.log.failed, 1);
  assert.equal(unreachable.log.navigate.length, 0);
});

// Keycloak live check B2: a failed renewal must not end a sign-in whose ID
// token still works.
test("a failed renewal keeps a token that still works; the banner waits for its exp or a 401 expired", () => {
  const now = 1_800_000_000_000;
  const exp = now / 1000 + 100; // inside the exp − 120 s window
  for (const reason of ["proactive", "visible", "redirect"]) {
    assert.equal(D.failedRenewalOutcome(reason, exp, now), "keep", reason);
  }
  assert.equal(D.failedRenewalOutcome("expired", exp, now), "expire", "sandboxd's 401 expired ends it, whatever this clock says");
  assert.equal(D.failedRenewalOutcome("proactive", now / 1000, now), "expire", "at exp the token has expired: strictly exp, no leeway");
  assert.equal(D.failedRenewalOutcome("proactive", now / 1000 - 30, now), "expire");
  assert.equal(D.failedRenewalOutcome("proactive", undefined, now), "expire", "no exp: nothing to keep");

  assert.equal(D.tokenLive(now / 1000 + 1, now), true);
  assert.equal(D.tokenLive(now / 1000, now), false);
  assert.equal(D.tokenLive("123", now), false);

  // After a failure the next try is at exp, not again at once: each try
  // for a code-flow provider is a full-page redirect.
  assert.equal(D.renewDelayMs(exp, now), 0, "inside the window");
  assert.equal(D.renewDelayMs(exp, now, true), 100 * 1000, "after a failure: at exp");
  assert.equal(D.renewDelayMs(now / 1000 - 5, now, true), 0, "already expired: now");
});

test("the renewer tells the page what started a failed renewal", async () => {
  const google = { issuer: "google", kind: "google", client: "c", url: "https://accounts.google.com", display: "Google" };
  const h = renewalHarness({ session: google, googleRenew: async () => false, fetch: () => response(200, {}) });
  assert.equal(await h.renewal.run("proactive"), false);
  assert.equal(await h.renewal.run("visible"), false);
  assert.deepEqual(h.log.failedReasons, ["proactive", "visible"]);
  assert.equal(h.log.expired, 0, "no 401 arrived: the session isn't ended here");

  const unreachable = renewalHarness({ beginRedirect: async () => { throw new Error("down"); } });
  assert.equal(await unreachable.renewal.run("proactive"), false);
  assert.deepEqual(unreachable.log.failedReasons, ["proactive"]);
  const recent = renewalHarness({ recentlyRenewed: true });
  assert.equal(await recent.renewal.run("visible"), false);
  assert.deepEqual(recent.log.failedReasons, ["visible"]);
});

test("a 401 expired that shares a failing proactive renewal still ends the session", async () => {
  const sent = deferred();
  const renewing = deferred();
  const h = renewalHarness({
    session: { issuer: "google", kind: "google", client: "c", url: "https://accounts.google.com", display: "Google" },
    googleRenew: () => renewing.promise,
    fetch: () => sent.promise,
  });
  const call = h.api("/v1/cluster/leader"); // in flight before the timer fires
  await flush();
  const proactive = h.renewal.run("proactive");
  sent.resolve(expired401()); // the 401 joins the proactive renewal
  await flush();
  renewing.resolve(false);
  assert.equal(await proactive, false);
  await assert.rejects(call, D.SessionExpired);
  assert.deepEqual(h.log.failedReasons, ["proactive"], "one renewal, started by the timer");
  assert.equal(h.log.expired, 1, "sandboxd's answer ends the session the proactive failure kept");

  // Its own renewal failing for an expired token: the page ends the
  // session through onFailed("expired"), and onExpired is a no-op there.
  const own = renewalHarness({ fetch: () => expired401(), recentlyRenewed: true });
  await assert.rejects(own.api("/health"), D.SessionExpired);
  assert.deepEqual(own.log.failedReasons, ["expired"]);
});

test("any other 401 is a rejection, worded by credential kind", async () => {
  const pat = renewalHarness({ kind: "pat", fetch: () => response(401, { error: "unauthorized" }) });
  await assert.rejects(pat.api("/health"), /unauthorized/);
  assert.deepEqual(pat.log.rejected, [["pat", ""]]);
  assert.equal(pat.log.beginRedirect.length, 0);

  const sso = renewalHarness({ fetch: () => response(401, { error: "unauthorized", reason: "invalid_signature" }) });
  await assert.rejects(sso.api("/health"));
  assert.deepEqual(sso.log.rejected, [["sso", "invalid_signature"]]);

  const avmExpired = renewalHarness({ kind: "avm", fetch: () => expired401() });
  await assert.rejects(avmExpired.api("/health"));
  assert.deepEqual(avmExpired.log.rejected, [["avm", "expired"]], "an expired API token can't renew");

  const notJSON = renewalHarness({ kind: "pat", fetch: () => ({ status: 401, ok: false, json: async () => { throw new Error("text"); } }) });
  await assert.rejects(notJSON.api("/health"));
  assert.deepEqual(notJSON.log.rejected, [["pat", ""]]);

  const down = renewalHarness({ fetch: async () => { throw new Error("offline"); } });
  await assert.rejects(down.api("/health"), /network: offline/);
  assert.equal(down.tracker.count(), 0, "a failed fetch still leaves the tracker");
});

test("the saved view round-trips, and a damaged one is dropped", () => {
  const v = { pageTokens: ["", "p2", "p3"], pageIndex: 2, autorefresh: false, open: ["metrics-raw-details"], scrollY: 840 };
  assert.deepEqual(JSON.parse(JSON.stringify(D.parseView(D.serializeView(v)))), v);
  assert.equal(D.parseView("{not json"), null);
  assert.equal(D.parseView("null"), null);
  const fixed = D.parseView(JSON.stringify({ pageTokens: [1], pageIndex: 9, open: ["ok", "bad id", 3], scrollY: -1 }));
  assert.deepEqual(JSON.parse(JSON.stringify(fixed)), { pageTokens: [""], pageIndex: 0, autorefresh: true, open: ["ok"], scrollY: 0 });
});

test("the tracker and single-flight primitives", async () => {
  const t = D.createTracker();
  let idle = false;
  t.begin(); t.begin();
  t.idle().then(() => { idle = true; });
  t.end();
  await flush(2);
  assert.equal(idle, false);
  t.end();
  await flush(2);
  assert.equal(idle, true);
  t.end();
  assert.equal(t.count(), 0, "never negative");

  let runs = 0;
  const gate = deferred();
  const sf = D.createSingleFlight(async () => { runs += 1; await gate.promise; return "done"; });
  const a = sf.run();
  const b = sf.run();
  assert.equal(a, b);
  assert.equal(sf.active(), true);
  gate.resolve();
  assert.equal(await a, "done");
  await sf.wait();
  assert.equal(sf.active(), false);
  assert.equal(runs, 1);
  await sf.run();
  assert.equal(runs, 2, "a later run starts a new flight");

  const failing = D.createSingleFlight(async () => { throw new Error("x"); });
  const p = failing.run();
  await failing.wait();
  await assert.rejects(p);
});

// ---------- DR7: sign out ----------

test("sign out clears the sign-in and the saved view and disables Google auto-select (DR7)", () => {
  const st = fakeStorage();
  for (const k of Object.values(D.KEYS)) { st.setItem(k, "x"); }
  const g = fakeGoogle();
  assert.equal(D.signOutSession(st, g), true);
  assert.deepEqual(g.calls, ["disableAutoSelect"], "auto-select is off, and no prompt() runs");
  for (const k of [D.KEYS.bearer, D.KEYS.sso, D.KEYS.pending, D.KEYS.view, D.KEYS.gisSignedOut]) {
    assert.equal(st.getItem(k), null, k);
  }
  assert.equal(st.getItem(D.KEYS.lastIssuer), "x", "the last issuer stays, for 'Use a different account'");
});

test("sign out before GIS has loaded disables auto-select as soon as it loads", () => {
  const st = fakeStorage();
  st.setItem(D.KEYS.bearer, "tok");
  assert.equal(D.signOutSession(st, undefined), false);
  assert.equal(st.getItem(D.KEYS.bearer), null);
  assert.equal(st.getItem(D.KEYS.gisSignedOut), "1");
  const g = fakeGoogle();
  assert.equal(D.applyDeferredSignOut(st, g), true);
  assert.deepEqual(g.calls, ["disableAutoSelect"]);
  assert.equal(D.applyDeferredSignOut(st, g), false, "only once");
  assert.deepEqual(g.calls, ["disableAutoSelect"]);
});

test("a GIS prompt that is skipped or dismissed without a credential is a failed renewal", () => {
  const n = (o) => Object.assign({ isSkippedMoment: () => false, isDismissedMoment: () => false, getDismissedReason: () => "" }, o);
  assert.equal(D.gisPromptGaveUp(null), false);
  assert.equal(D.gisPromptGaveUp(n({})), false);
  assert.equal(D.gisPromptGaveUp(n({ isSkippedMoment: () => true })), true);
  assert.equal(D.gisPromptGaveUp(n({ isDismissedMoment: () => true, getDismissedReason: () => "cancel_called" })), true);
  assert.equal(D.gisPromptGaveUp(n({ isDismissedMoment: () => true, getDismissedReason: () => "credential_returned" })), false);
  assert.equal(D.gisPromptGaveUp({ getMomentType: () => "display" }), false, "a FedCM notification without the old methods");
});

test("the overview's capacity roll-up is unchanged", () => {
  const agg = D.aggregateCapacity([
    { alive: true, capacity: { host_cpu_cores: 8, cpu_budget: 8, reserved_cpu: 2, sandboxes_active: 3 } },
    { alive: false, drained: true, capacity: { host_cpu_cores: 8, cpu_budget: 8 } },
  ]);
  assert.equal(agg.nodes, 2);
  assert.equal(agg.alive, 1);
  assert.equal(agg.drained, 1);
  assert.equal(agg.sandboxes, 3);
  assert.equal(agg.availableCPU, 6);
});

test("the metrics panel reads /v1/metrics: unlabeled samples by name, comments dropped", () => {
  // The shape writePrometheusExpvars renders (pkg/api/prometheus.go).
  const text = [
    "# HELP aerolvm_gossip_members_alive AerolVM expvar metric aerolvm_gossip_members_alive.",
    "# TYPE aerolvm_gossip_members_alive gauge",
    "aerolvm_gossip_members_alive 8",
    "# HELP aerolvm_identity_jwks_fetch_total AerolVM expvar metric aerolvm_identity_jwks_fetch_total.",
    "# TYPE aerolvm_identity_jwks_fetch_total counter",
    "aerolvm_identity_jwks_fetch_total{key=\"keycloak\",key2=\"ok\"} 3",
    "aerolvm_raft_apply_last_nanos 1.5e+06",
    "aerolvm_raft_apply_total 42",
    "aerolvm_broken_sample not-a-number",
    "",
  ].join("\n");
  const { values, lines } = D.parsePrometheusText(text);
  assert.deepEqual(JSON.parse(JSON.stringify(values)), {
    aerolvm_gossip_members_alive: 8,
    aerolvm_raft_apply_last_nanos: 1500000,
    aerolvm_raft_apply_total: 42,
  });
  assert.equal(lines.length, 5, "every sample line, labeled or not, is kept for the raw view");
  assert.ok(lines.every((l) => !l.startsWith("#")), "no HELP or TYPE comment in the raw view");
  assert.deepEqual(JSON.parse(JSON.stringify(D.parsePrometheusText(""))), { values: {}, lines: [] });
  assert.deepEqual(JSON.parse(JSON.stringify(D.parsePrometheusText(undefined))), { values: {}, lines: [] });
});
