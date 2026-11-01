// Messagerie d'un participant : accueil, contacts, conversation, panneau d'inspection.

const TOGGLES = {
  rsa: [
    { key: "encrypt", icon: "lock", label: "Chiffrer", on: true },
    { key: "sign", icon: "pen", label: "Signer", on: true },
  ],
  ecc: [
    { locked: true, icon: "lock", label: "Chiffré, toujours" },
    { key: "sign", icon: "pen", label: "Signer (ECDSA)", on: true },
  ],
  elgamal: [
    { key: "encrypt", icon: "lock", label: "Chiffrer", on: true },
    { key: "sign", icon: "pen", label: "Signer", on: true },
    { key: "reuse_k", icon: "alert", label: "Même k (faille)", on: false, risky: true },
  ],
};

const options = {};
for (const [sid, list] of Object.entries(TOGGLES)) {
  options[sid] = Object.fromEntries(list.filter(t => t.key).map(t => [t.key, t.on]));
}

const ui = { scheme: "rsa", peer: null, selected: null, panel: null };
const seen = new Set();
const revealed = new Set();
const memo = {};
let data = null;

const $ = id => document.getElementById(id);

function changed(part, key) {
  if (memo[part] === key) return false;
  memo[part] = key;
  return true;
}

function initial(name) {
  return (name || "?").trim().slice(0, 1).toUpperCase();
}

function conversation(scheme = ui.scheme, peer = ui.peer) {
  return data.messages.filter(m => m.scheme === scheme && m.peer === peer);
}

function unread(filter) {
  return data.messages.filter(m => m.direction === "in" && !seen.has(m.id) && filter(m)).length;
}

// --- Barre latérale ----------------------------------------------------------

function renderSidebar() {
  $("me-name").textContent = data.me;
  $("me-avatar").textContent = initial(data.me);
  $("conn-dot").className = "dot " + (data.connected ? "on" : "off");
  $("conn-text").textContent = data.connected ? "Connecté au relais" : (data.error || "Relais injoignable");
  $("conn-text").title = data.relay;

  const protoKey = JSON.stringify([ui.scheme, Object.keys(SCHEMES).map(s => unread(m => m.scheme === s))]);
  if (changed("protocols", protoKey)) {
    $("protocols").replaceChildren(...Object.entries(SCHEMES).map(([sid, s]) => {
      const n = sid === ui.scheme ? 0 : unread(m => m.scheme === sid);
      return h("button", { class: "side-item" + (sid === ui.scheme ? " active" : ""), onclick: () => select({ scheme: sid }) },
        h("span", { class: "proto-code" }, s.code),
        h("span", { class: "grow" }, h("span", { class: "title" }, s.title), h("span", { class: "sub" }, s.tagline)),
        n ? h("span", { class: "badge" }, n) : null);
    }));
  }

  const peers = Object.keys(data.peers);
  const contactKey = JSON.stringify([ui.scheme, ui.peer, peers.map(p => [p, conversation(ui.scheme, p).length, unread(m => m.peer === p && m.scheme === ui.scheme)])]);
  if (changed("contacts", contactKey)) {
    $("contacts").replaceChildren(...(peers.length ? peers.map(p => {
      const conv = conversation(ui.scheme, p);
      const last = conv[conv.length - 1];
      const n = p === ui.peer ? 0 : unread(m => m.peer === p && m.scheme === ui.scheme);
      const sub = last ? (last.direction === "out" ? "Vous : " : "") + (last.text ?? "message illisible") : "Aucun message";
      return h("button", { class: "side-item" + (p === ui.peer ? " active" : ""), onclick: () => select({ peer: p }) },
        h("span", { class: "avatar" }, initial(p)),
        h("span", { class: "grow" }, h("span", { class: "title" }, p), h("span", { class: "sub" }, sub)),
        n ? h("span", { class: "badge" }, n) : null);
    }) : [h("p", { class: "side-empty" }, "Personne d'autre n'est connecté pour l'instant.")]));
  }
}

// --- Conversation ------------------------------------------------------------

function renderHeader() {
  const s = SCHEMES[ui.scheme];
  $("chat-title").textContent = ui.peer ? ui.peer : s.title;
  $("chat-sub").textContent = ui.peer ? `${s.title} · ${s.detail}` : s.detail;
  $("btn-help").className = "btn ghost" + (ui.panel === "help" ? " on" : "");
  $("btn-keys").className = "btn ghost" + (ui.panel === "keys" ? " on" : "");
}

function renderToggles() {
  $("toggles").replaceChildren(...TOGGLES[ui.scheme].map(t => {
    if (t.locked) return h("span", { class: "toggle on locked" }, icon(t.icon), t.label);
    const on = options[ui.scheme][t.key];
    return h("button", {
      type: "button", class: `toggle${on ? " on" : ""}${t.risky ? " risky" : ""}`, "aria-pressed": String(on),
      onclick: () => { options[ui.scheme][t.key] = !on; renderToggles(); },
    }, icon(t.icon), t.label);
  }));
}

function statusLine(m) {
  const parts = [];
  if (m.direction === "out") {
    const o = m.options || {};
    const encrypted = ui.scheme === "ecc" || o.encrypt !== false;
    parts.push(h("span", {}, icon(encrypted ? "lock" : "unlock"), encrypted ? "Chiffré" : "En clair"));
    parts.push(h("span", {}, icon("pen"), o.sign === false ? "Non signé" : "Signé"));
    if (o.reuse_k && o.sign !== false) parts.push(h("span", { class: "warn" }, "même k"));
  } else if (m.text === null) {
    parts.push(h("span", { class: "bad" }, icon("x"), "Déchiffrement impossible"));
  } else {
    const v = verdictOf(m);
    const p = m.props;
    if (p.confidentialite.state !== "ok") parts.push(h("span", { class: "warn" }, icon("unlock"), "En clair"));
    if (v.tone === "bad") parts.push(h("span", { class: "bad" }, icon("alert"), "Signature invalide"));
    else if (p.non_repudiation.state === "ok") parts.push(h("span", { class: "good" }, icon("seal"), `Signé par ${m.peer}`));
    else if (p.authenticite.state === "ok") parts.push(h("span", {}, icon("lock"), "Chiffré, non signé"));
    else parts.push(h("span", { class: "warn" }, icon("alert"), "Non signé"));
  }
  parts.push(h("span", {}, fmtTime(m.time)));
  return h("div", { class: "status" }, parts);
}

function renderMessages() {
  const list = ui.peer ? conversation() : [];
  if (!changed("messages", JSON.stringify([ui.scheme, ui.peer, ui.selected, list.map(m => m.id)]))) return;
  const box = $("messages");
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;

  if (!ui.peer) {
    box.replaceChildren(h("div", { class: "blank" },
      h("h2", {}, "En attente d'un correspondant"),
      h("p", {}, "Demandez à l'autre personne de lancer ", h("code", {}, "client.py"),
        " sur son ordinateur et de rejoindre le même relais.")));
  } else if (!list.length) {
    box.replaceChildren(h("div", { class: "blank" },
      h("h2", {}, `Écrivez à ${ui.peer}`),
      h("p", {}, `Votre message sera protégé avec ${SCHEMES[ui.scheme].title}. Cliquez ensuite dessus pour voir ce qui s'est passé.`)));
  } else {
    box.replaceChildren(...list.map(m => {
      const failed = m.direction === "in" && m.text === null;
      const forged = m.direction === "in" && !failed && verdictOf(m).tone === "bad";
      return h("div", { class: `msg ${m.direction}${m.id === ui.selected ? " selected" : ""}` },
        h("button", {
          class: "bubble" + (failed ? " failed" : "") + (forged ? " forged" : ""), type: "button",
          onclick: () => openMessage(m.id),
        }, failed ? [icon("x"), "Ce message n'a pas pu être déchiffré"] : m.text),
        statusLine(m));
    }));
  }
  if (nearBottom || memo.lastConv !== ui.scheme + ui.peer) box.scrollTop = box.scrollHeight;
  memo.lastConv = ui.scheme + ui.peer;
  for (const m of list) seen.add(m.id);
}

function renderComposer() {
  const ready = Boolean(ui.peer);
  $("text").disabled = !ready;
  $("text").placeholder = ready ? `Message à ${ui.peer}` : "Aucun correspondant connecté";
  $("send").disabled = !ready;
}

// --- Panneau d'inspection ----------------------------------------------------

function kvRow(id, item) {
  const hidden = item.secret && !revealed.has(id);
  return h("div", { class: "kv" },
    h("div", { class: "kv-head" }, h("span", {}, item.label),
      item.secret ? h("button", {
        class: "lnk", type: "button",
        onclick: () => { revealed.has(id) ? revealed.delete(id) : revealed.add(id); memo.panel = null; renderPanel(); },
      }, hidden ? "Afficher" : "Masquer") : null),
    hidden ? h("p", { class: "masked" }, "•••••••• masquée") : valueBox(item.value));
}

function messagePanel(m) {
  const head = m.direction === "out"
    ? h("div", { class: "verdict" }, icon("send"), h("div", {}, h("strong", {}, `Envoyé à ${m.peer}`),
      h("p", {}, `${fmtTimeFull(m.time)} · paquet n° ${m.packet_id}`)))
    : verdictBox(verdictOf(m));
  return [
    h("div", { class: "section" }, head,
      m.text !== null ? h("p", { class: "quoted" }, m.text) : null),
    m.props ? h("div", { class: "section" }, h("h3", {}, "Garanties de sécurité"), checks(m.props)) : null,
    h("div", { class: "section" },
      h("h3", {}, m.direction === "out" ? "Ce que votre ordinateur a fait avant l'envoi" : "Ce que votre ordinateur a vérifié"),
      timeline(m.steps)),
  ];
}

function keysPanel() {
  const mine = data.keys[ui.scheme];
  const peers = Object.entries(data.peers);
  return [
    h("div", { class: "section" },
      h("h3", {}, "Mes clés"),
      h("p", { class: "fp", style: "margin-bottom:10px" }, `Empreinte publique ${mine.fingerprint}`),
      mine.info.map((item, i) => kvRow(`me-${ui.scheme}-${i}`, item))),
    h("div", { class: "section" },
      h("h3", {}, "Contacts"),
      peers.length ? peers.map(([name, p]) => h("div", { class: "contact-card" },
        h("div", { class: "top" }, h("span", { class: "avatar" }, initial(name)), h("strong", { style: "flex:1" }, name),
          h("span", { class: "fp" }, p[ui.scheme].fingerprint)),
        p[ui.scheme].info.length
          ? h("div", { class: "kvs" }, p[ui.scheme].info.map((item, i) => kvRow(`${name}-${ui.scheme}-${i}`, item)))
          : null))
        : h("p", { class: "fp" }, "Aucun contact connecté.")),
  ];
}

function renderPanel() {
  const m = ui.panel === "message" ? data.messages.find(x => x.id === ui.selected) : null;
  if (ui.panel === "message" && !m) ui.panel = null;
  const key = JSON.stringify([ui.panel, ui.scheme, m?.id, ui.panel === "keys" ? [data.peers, [...revealed]] : 0]);
  if (!changed("panel", key)) return;
  $("inspector").hidden = !ui.panel;
  if (!ui.panel) return;
  const titles = { message: "Détails du message", help: `Comment fonctionne ${SCHEMES[ui.scheme].title}`, keys: `Clés ${SCHEMES[ui.scheme].title}` };
  $("insp-title").textContent = titles[ui.panel];
  const body = $("insp-body");
  if (ui.panel === "help") body.replaceChildren(h("div", { html: SCHEMES[ui.scheme].help }));
  else body.replaceChildren(...[ui.panel === "keys" ? keysPanel() : messagePanel(m)].flat(2).filter(Boolean));
}

// --- Navigation --------------------------------------------------------------

function select(change) {
  Object.assign(ui, change);
  if (ui.panel === "message") ui.panel = null;
  ui.selected = null;
  $("send-error").hidden = true;
  if ("scheme" in change) renderToggles();
  render();
}

function openMessage(id) {
  if (ui.selected === id && ui.panel === "message") { closePanel(); return; }
  ui.selected = id;
  ui.panel = "message";
  render();
}

function togglePanel(name) {
  ui.panel = ui.panel === name ? null : name;
  ui.selected = null;
  render();
}

function closePanel() {
  ui.panel = null;
  ui.selected = null;
  render();
}

function render() {
  const peers = Object.keys(data.peers);
  if (!peers.includes(ui.peer)) ui.peer = peers[0] || null;
  renderSidebar();
  renderHeader();
  renderMessages();
  renderComposer();
  renderPanel();
  document.title = `${data.me} · Messagerie chiffrée`;
}

// --- Échanges avec le programme local ----------------------------------------

async function refresh() {
  let state;
  try {
    state = await api("/api/state");
  } catch {
    if (data) { $("conn-dot").className = "dot off"; $("conn-text").textContent = "Programme local arrêté"; }
    return;
  }
  if (!state.joined) {
    $("join").hidden = false;
    $("app").hidden = true;
    if (!$("join-relay").value) {
      // Une adresse passée avec --relay l'emporte ; sinon on reprend celle de la dernière fois.
      const given = state.relay && !state.relay.includes("127.0.0.1") ? state.relay : null;
      $("join-relay").value = given || rememberedRelay() || state.relay || "";
    }
    return;
  }
  const first = !data;
  data = state;
  if (first) {
    $("join").hidden = true;
    $("app").hidden = false;
    renderToggles();
  }
  render();
}

function rememberedRelay() {
  try { return localStorage.getItem("relay"); } catch { return null; }
}

$("join-form").addEventListener("submit", async e => {
  e.preventDefault();
  const btn = $("join-btn");
  btn.disabled = true;
  btn.textContent = "Création de vos clés…";
  $("join-error").hidden = true;
  try {
    await api("/api/join", { name: $("join-name").value, relay: $("join-relay").value });
    try { localStorage.setItem("relay", $("join-relay").value); } catch { /* stockage indisponible */ }
    await refresh();
  } catch (ex) {
    $("join-error").textContent = ex.message;
    $("join-error").hidden = false;
  } finally {
    btn.disabled = false;
    btn.textContent = "Rejoindre";
  }
});

$("composer").addEventListener("submit", async e => {
  e.preventDefault();
  const text = $("text").value.trim();
  if (!text || !ui.peer) return;
  $("send").disabled = true;
  try {
    await api("/api/send", { scheme: ui.scheme, to: ui.peer, text, options: options[ui.scheme] });
    $("text").value = "";
    autosize();
    $("send-error").hidden = true;
    await refresh();
    const box = $("messages");
    box.scrollTop = box.scrollHeight;
  } catch (ex) {
    $("send-error").textContent = ex.message;
    $("send-error").hidden = false;
  } finally {
    renderComposer();
    $("text").focus();
  }
});

function autosize() {
  const t = $("text");
  t.style.height = "auto";
  t.style.height = Math.min(t.scrollHeight, 160) + "px";
}

$("text").addEventListener("input", autosize);
$("text").addEventListener("keydown", e => {
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    $("composer").requestSubmit();
  }
});
document.addEventListener("keydown", e => { if (e.key === "Escape" && ui.panel) closePanel(); });

$("btn-help").append(icon("help"), h("span", { class: "label" }, "Comment ça marche"));
$("btn-keys").append(icon("key"), h("span", { class: "label" }, "Clés"));
$("btn-help").addEventListener("click", () => togglePanel("help"));
$("btn-keys").addEventListener("click", () => togglePanel("keys"));
$("insp-close").append(icon("x"));
$("insp-close").addEventListener("click", closePanel);
$("send").append(icon("send"));
$("brand-mark").append(icon("lock"));

refresh();
setInterval(refresh, 1000);
