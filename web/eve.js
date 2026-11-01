// Console d'Eve : trafic intercepté, écoute / interception, lecture, falsification, attaque El-Gamal.

const MODES = {
  passive: { label: "Écoute", icon: "radio", hint: "Je copie tout ce qui passe. Les messages arrivent normalement." },
  active: { label: "Interception", icon: "bolt", hint: "Chaque message est retenu jusqu'à ma décision." },
};
const STATES = { transmis: "Transmis", en_attente: "Retenu", modifie: "Modifié", bloque: "Bloqué" };
const SIGNATURE_MODES = {
  keep: "Garder la signature d'origine",
  none: "Supprimer la signature",
  eve: "Signer avec ma propre clé",
};

const ui = { filter: "all", view: null }; // view : {packet: id} ou {attack: "id1-id2"}
const memo = {};
let data = null;

const $ = id => document.getElementById(id);

function changed(part, key) {
  if (memo[part] === key) return false;
  memo[part] = key;
  return true;
}

function isEncrypted(p) {
  return p.scheme === "ecc" || p.payload.encrypted;
}

function cipherSample(p) {
  const pl = p.payload;
  const raw = p.scheme === "ecc" ? pl.ciphertext : p.scheme === "rsa" ? pl.blocks[0] : pl.blocks[0][1];
  return raw.slice(0, 36) + "…";
}

// --- Barre du haut -----------------------------------------------------------

function renderBar() {
  $("where").textContent = "Relais réseau";
  const net = data.network || {};
  $("share").hidden = !net.url;
  $("share-url").textContent = net.url || "";
  for (const b of $("mode").children) {
    const on = b.dataset.mode === data.mode;
    b.className = (on ? "on" : "") + (b.dataset.mode === "active" ? " intercept" : "");
  }
  $("mode-hint").textContent = MODES[data.mode].hint;

  if (changed("people", JSON.stringify([data.participants.map(p => [p.name, p.addr, p.online]), data.stolen]))) {
    $("people").replaceChildren(...(data.participants.length
      ? data.participants.map(p => h("span", { title: p.addr },
        h("span", { class: "dot " + (p.online ? "on" : "off") }), h("b", {}, p.name), p.addr,
        data.stolen.includes(p.name) ? h("span", { class: "tag-stolen" }, "clé volée") : null))
      : [h("span", {}, "Aucun participant connecté")]));
  }
}

// --- Liste du trafic ---------------------------------------------------------

function renderFilters() {
  if (!changed("filters", ui.filter)) return;
  const items = [["all", "Tout"], ...Object.entries(SCHEMES).map(([sid, s]) => [sid, s.code === "ELG" ? "El-Gamal" : s.code])];
  $("filters").replaceChildren(...items.map(([id, label]) =>
    h("button", { type: "button", class: ui.filter === id ? "on" : "", onclick: () => { ui.filter = id; render(); } }, label)));
}

function renderAlerts() {
  const held = data.packets.filter(p => p.status === "en_attente");
  const net = data.network || {};
  const blocked = net.wsl_nat && !net.forwarded;
  const key = JSON.stringify([blocked, held.map(p => p.id), data.attacks.map(a => [a.ids, a.result?.success])]);
  if (!changed("alerts", key)) return;
  const items = [];
  if (blocked) {
    items.push(h("div", { class: "alert net" }, icon("alert"),
      h("div", { class: "grow" },
        h("strong", {}, "Les autres machines ne peuvent pas encore joindre ce relais."),
        h("p", {}, `WSL2 est en mode NAT : Windows doit rediriger le port vers Linux (${net.wsl_ip}). `
          + "Relancez avec --wsl-forward, ou exécutez dans un PowerShell administrateur :"),
        h("pre", { class: "raw" }, (net.commands || []).join("\n")))));
  }
  if (held.length) {
    const oldest = held[held.length - 1];
    items.push(h("div", { class: "alert held" }, icon("bolt"),
      h("span", { class: "grow" }, held.length > 1 ? `${held.length} messages retenus attendent votre décision.` : "Un message retenu attend votre décision."),
      h("button", { class: "btn", type: "button", onclick: () => show({ packet: oldest.id }) }, "Traiter")));
  }
  for (const a of data.attacks) {
    const key = a.ids.join("-");
    const done = a.result?.success;
    items.push(h("div", { class: "alert" }, icon(done ? "key" : "alert"),
      h("span", { class: "grow" }, done
        ? `Clé privée El-Gamal de ${a.victim} retrouvée.`
        : `${a.victim} a signé deux messages (#${a.ids[0]} et #${a.ids[1]}) avec le même k.`),
      done
        ? h("button", { class: "btn", type: "button", onclick: () => show({ attack: key }) }, "Voir le calcul")
        : h("button", { class: "btn primary", type: "button", onclick: () => attack(a) }, "Retrouver sa clé privée")));
  }
  $("alerts").replaceChildren(...items);
}

function renderRows() {
  const list = data.packets.filter(p => ui.filter === "all" || p.scheme === ui.filter);
  $("count").textContent = `${data.packets.length} paquet${data.packets.length > 1 ? "s" : ""}`;
  const key = JSON.stringify([ui.filter, ui.view, list.map(p => [p.id, p.status, p.modified])]);
  if (!changed("rows", key)) return;
  if (!list.length) {
    $("rows").replaceChildren(h("div", { class: "blank" },
      h("h2", {}, "Rien n'est encore passé"),
      h("p", {}, "Les messages envoyés par les participants apparaîtront ici en temps réel.")));
    return;
  }
  $("rows").replaceChildren(...list.map(p => {
    const pl = p.payload;
    const content = isEncrypted(p)
      ? h("span", { class: "content" }, h("span", { class: "mono" }, cipherSample(p)))
      : h("span", { class: "content" }, h("span", { class: "clear" }, `« ${pl.plaintext} »`));
    return h("button", {
      type: "button", class: "row" + (ui.view?.packet === p.id ? " selected" : ""),
      onclick: () => show(ui.view?.packet === p.id ? null : { packet: p.id }),
    },
      h("span", { class: "mono" }, `#${p.id}`),
      h("span", { class: "mono time" }, fmtTimeFull(p.time)),
      h("span", { class: "proto" }, SCHEMES[p.scheme].code),
      h("span", { class: "route" }, p.from, icon("arrow"), p.to),
      content,
      h("span", { class: `state ${p.status}` }, STATES[p.status]));
  }));
}

// --- Panneau d'inspection ----------------------------------------------------

function overview() {
  return [
    h("div", { class: "section prose" },
      h("p", {}, "Tous les messages entre les participants passent par ce relais. Je vois les clés publiques et les paquets, mais je n'ai aucune clé privée d'Alice ou de Bob."),
      h("p", {}, "En écoute, je copie tout et j'essaie de lire. En interception, je retiens chaque message : je peux le transmettre, l'altérer, le remplacer ou le bloquer.")),
    h("div", { class: "section" }, h("h3", {}, "Pour commencer"),
      h("div", { class: "callout" }, "Cliquez sur un paquet de la liste pour voir son contenu brut et tenter de le lire.")),
  ];
}

function packetPanel(p) {
  const held = p.status === "en_attente";
  const encrypted = isEncrypted(p);
  const nodes = [
    h("div", { class: "section" },
      h("p", { class: "fp" }, `${SCHEMES[p.scheme].title} · ${p.from} → ${p.to} · ${fmtTimeFull(p.time)}`),
      h("p", { style: "margin-top:6px" }, h("span", { class: `state ${p.status}` }, STATES[p.status])),
      p.notes.length ? h("ul", { class: "notes" }, p.notes.map(n => h("li", {}, icon("edit"), n))) : null),
    h("div", { class: "section" }, h("h3", {}, "Ce qui passe sur le réseau"),
      h("pre", { class: "raw" }, JSON.stringify(p.payload, null, 2))),
  ];

  const read = h("div", { class: "section" }, h("h3", {}, "Lecture"),
    h("button", { class: "btn", type: "button", onclick: () => readPacket(p.id) },
      icon("eye"), encrypted ? "Essayer de déchiffrer" : "Lire le message"));
  if (p.eve_read) {
    read.append(h("div", { class: "readout" },
      p.eve_read.success ? h("p", { class: "quoted", style: "margin:0 0 14px" }, p.eve_read.text) : null,
      timeline(p.eve_read.steps)));
  }
  nodes.push(read);

  if (held) {
    const text = h("textarea", { rows: 3, placeholder: "Texte à faire passer pour l'original" });
    if (!encrypted) text.value = p.payload.plaintext;
    const sig = h("select", {}, p.replace_modes.map(m => h("option", { value: m },
      m === "stolen" ? `Signer avec la clé volée de ${p.from}` : SIGNATURE_MODES[m])));
    nodes.push(h("div", { class: "section" }, h("h3", {}, "Décision"),
      h("div", { class: "decision" },
        h("button", { class: "btn primary", type: "button", onclick: () => act(p.id, "forward") }, icon("arrow"), "Transmettre"),
        h("button", { class: "btn", type: "button", onclick: () => act(p.id, "tamper") }, icon("bolt"),
          encrypted ? "Altérer le chiffré" : "Altérer le texte"),
        h("button", { class: "btn danger", type: "button", onclick: () => act(p.id, "block") }, icon("ban"), "Bloquer")),
      h("div", { class: "replace" },
        h("strong", {}, "Remplacer le message"),
        text, sig,
        h("div", {}, h("button", {
          class: "btn", type: "button", onclick: () => act(p.id, "replace", { text: text.value, signature: sig.value }),
        }, icon("edit"), "Remplacer et transmettre")))));
  }
  return nodes;
}

function attackPanel(a) {
  return [
    h("div", { class: "section" }, verdictBox({
      tone: "bad", icon: "key", title: `Clé privée de ${a.victim} retrouvée`,
      text: `Je peux lire les messages El-Gamal adressés à ${a.victim} et signer à sa place (Interception → Remplacer).`,
    })),
    h("div", { class: "section" }, h("h3", {}, "Le calcul"), timeline(a.result.steps)),
  ];
}

function renderPanel() {
  const p = ui.view?.packet ? data.packets.find(x => x.id === ui.view.packet) : null;
  const a = ui.view?.attack ? data.attacks.find(x => x.ids.join("-") === ui.view.attack && x.result) : null;
  if (ui.view && !p && !a) ui.view = null;
  const key = JSON.stringify(p ? [p.id, p.status, p.notes, p.eve_read, p.replace_modes] : a ? a.ids : "overview");
  if (!changed("panel", key)) return;
  $("inspector").classList.toggle("idle", !ui.view);
  $("insp-title").textContent = p ? `Paquet #${p.id}` : a ? "Attaque sur El-Gamal" : "Console d'Eve";
  $("insp-close").hidden = !ui.view;
  $("insp-body").replaceChildren(...[p ? packetPanel(p) : a ? attackPanel(a) : overview()].flat(2).filter(Boolean));
}

function render() {
  renderBar();
  renderFilters();
  renderAlerts();
  renderRows();
  renderPanel();
}

function show(view) {
  ui.view = view;
  render();
}

// --- Actions -----------------------------------------------------------------

async function refresh() {
  try {
    data = await api("/eve/api/state");
    render();
  } catch {
    $("where").textContent = "Relais arrêté";
  }
}

async function readPacket(id) {
  await api(`/eve/api/packets/${id}/read`, {});
  await refresh();
}

async function act(id, action, body) {
  try {
    await api(`/eve/api/packets/${id}/${action}`, body || {});
  } catch (e) {
    memo.panel = null;
  }
  await refresh();
}

async function attack(a) {
  await api("/eve/api/attack/elgamal", { ids: a.ids });
  ui.view = { attack: a.ids.join("-") };
  await refresh();
}

for (const b of $("mode").children) {
  const m = MODES[b.dataset.mode];
  b.append(icon(m.icon), m.label);
  b.addEventListener("click", async () => {
    await api("/eve/api/mode", { mode: b.dataset.mode });
    await refresh();
  });
}
$("insp-close").append(icon("x"));
$("insp-close").addEventListener("click", () => show(null));
$("share-copy").append("Copier");
$("share-copy").addEventListener("click", async () => {
  const btn = $("share-copy");
  try {
    await navigator.clipboard.writeText($("share-url").textContent);
    btn.textContent = "Copiée";
  } catch {
    getSelection().selectAllChildren($("share-url"));
    btn.textContent = "Sélectionnée";
  }
  setTimeout(() => { btn.textContent = "Copier"; }, 1500);
});
document.addEventListener("keydown", e => { if (e.key === "Escape" && ui.view) show(null); });

refresh();
setInterval(refresh, 1000);
