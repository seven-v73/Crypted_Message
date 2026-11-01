// Outils partagés par la page d'un participant et la console d'Eve.

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "html") el.innerHTML = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const ICONS = {
  lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>',
  unlock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7.5a4 4 0 0 1 7.6-1.7"/>',
  pen: '<path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17z"/><path d="M14 8l2 2"/>',
  seal: '<path d="M12 3l2.3 1.7 2.9-.1.9 2.7 2.3 1.8-.9 2.7.9 2.7-2.3 1.8-.9 2.7-2.9-.1L12 21l-2.3-1.7-2.9.1-.9-2.7-2.3-1.8.9-2.7-.9-2.7 2.3-1.8.9-2.7 2.9.1z"/><path d="M9 12l2 2 4-4"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
  x: '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>',
  minus: '<path d="M7 12h10"/>',
  alert: '<path d="M10.3 4.3L2.9 17.5A2 2 0 0 0 4.6 20.5h14.8a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4M12 17h.01"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M10.8 12.2L20 3M16.5 6.5l3 3M14 9l2 2"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.6 9.3a2.5 2.5 0 1 1 3.3 2.4c-.6.2-.9.8-.9 1.4v.6M12 16.8h.01"/>',
  send: '<path d="M5 12h13M12 5.5L18.5 12 12 18.5"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.8"/>',
  ban: '<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>',
  bolt: '<path d="M13 3L5 13.5h6l-1 7.5 8-10.5h-6z"/>',
  edit: '<path d="M4 20h16M6 16l9.5-9.5a2.1 2.1 0 0 1 3 3L9 19H6z"/>',
  radio: '<circle cx="12" cy="12" r="2"/><path d="M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7M5.6 5.6a9 9 0 0 0 0 12.8M18.4 5.6a9 9 0 0 1 0 12.8"/>',
};

function icon(name) {
  const span = document.createElement("span");
  span.innerHTML = `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`;
  return span.firstChild;
}

async function api(url, body) {
  const opts = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Erreur ${res.status}`);
  return data;
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

function fmtTimeFull(ts) {
  return new Date(ts * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// Valeur technique repliée sur trois lignes ; un clic l'ouvre en entier.
function valueBox(text) {
  const box = h("code", { class: "value", title: "Cliquer pour tout afficher" }, text);
  box.addEventListener("click", () => box.classList.toggle("open"));
  return box;
}

// Une phrase d'explication s'affiche comme du texte ; une clé, un chiffré ou un nombre comme une valeur technique.
function isProse(text) {
  return /[a-zà-ÿ]{3,} [a-zà-ÿ]{2,}/i.test(text) && !/\S{40,}/.test(text);
}

function timeline(steps) {
  return h("ol", { class: "timeline" }, steps.map(s =>
    h("li", { class: s.state || "" }, h("span", {}, s.label),
      s.value ? (isProse(s.value) ? h("p", { class: "step-note" }, s.value) : valueBox(s.value)) : null)));
}

const GUARANTEES = [
  ["confidentialite", "Confidentialité"],
  ["integrite", "Intégrité"],
  ["authenticite", "Authenticité"],
  ["non_repudiation", "Non-répudiation"],
];

function checks(props) {
  return h("div", { class: "checks" }, GUARANTEES.map(([key, name]) => {
    const p = props[key];
    return h("div", { class: `check ${p.state}` },
      h("span", { class: "mark" }, icon(p.state === "ok" ? "check" : p.state === "fail" ? "x" : "minus")),
      h("strong", {}, name),
      h("p", {}, p.text));
  }));
}

// Résumé d'un message reçu, à partir des garanties calculées par le destinataire.
function verdictOf(m) {
  if (m.text === null) {
    return { tone: "bad", icon: "x", title: "Impossible de déchiffrer ce message",
      text: "Le contenu a été modifié en route ou n'a pas été chiffré pour vous." };
  }
  const p = m.props;
  if (p.integrite.state === "fail" || p.authenticite.state === "fail") {
    return { tone: "bad", icon: "alert", title: "Message altéré ou falsifié",
      text: `La signature ne correspond pas : ce texte n'est pas celui que ${m.peer} a signé.` };
  }
  if (p.non_repudiation.state === "ok") {
    return { tone: "good", icon: "seal", title: `Authentique, signé par ${m.peer}`,
      text: p.confidentialite.state === "ok" ? "Intact, et personne d'autre n'a pu le lire." : "Intact, mais il a circulé en clair." };
  }
  if (p.authenticite.state === "ok") {
    return { tone: "good", icon: "lock", title: "Chiffré et intact",
      text: `Seul ${m.peer} a pu l'écrire, mais sans signature il ne peut pas le prouver à un tiers.` };
  }
  return { tone: "warn", icon: "alert", title: "Message non vérifiable",
    text: "Il n'est pas signé : impossible de savoir s'il a été modifié ni qui l'a écrit." };
}

function verdictBox(v) {
  return h("div", { class: `verdict ${v.tone}` }, icon(v.icon), h("div", {}, h("strong", {}, v.title), h("p", {}, v.text)));
}

// --- Textes d'explication ----------------------------------------------------

const M = s => `<span class="math">${s}</span>`;

const SCHEMES = {
  rsa: {
    code: "RSA",
    title: "RSA",
    tagline: "Confidentialité, intégrité, authenticité, non-répudiation",
    detail: "Chiffrement RSA-OAEP 2048 bits · signature RSA-PSS",
    help: `
      <div class="prose"><p>Chaque personne possède deux clés liées : une clé publique, que tout le monde connaît,
      et une clé privée, qui ne quitte jamais son ordinateur.</p></div>
      <div class="flow">
        <div class="stage" data-n="1"><h4>Chez l'expéditeur</h4><ul>
          <li>Calcule l'empreinte SHA-256 du message.</li>
          <li>Signe cette empreinte avec <b>sa clé privée</b>.</li>
          <li>Chiffre le message avec la <b>clé publique du destinataire</b>.</li></ul></div>
        <div class="stage net" data-n="2"><h4>Sur le réseau</h4><p>Eve voit passer un bloc chiffré et une signature.
          Sans la clé privée du destinataire, elle ne peut pas lire. Sans celle de l'expéditeur, elle ne peut pas signer à sa place.</p></div>
        <div class="stage" data-n="3"><h4>Chez le destinataire</h4><ul>
          <li>Déchiffre avec sa clé privée : <b>confidentialité</b>.</li>
          <li>Recalcule l'empreinte et vérifie la signature avec la clé publique de l'expéditeur : <b>intégrité</b> et <b>authenticité</b>.</li>
          <li>La signature reste vérifiable par n'importe qui : <b>non-répudiation</b>.</li></ul></div>
      </div>
      <div class="callout">À essayer : décochez « Chiffrer » ou « Signer » avant d'envoyer, et regardez quelle garantie disparaît chez le destinataire.</div>`,
  },
  ecc: {
    code: "ECC",
    title: "Courbes elliptiques",
    tagline: "Échange de clé et messages sécurisés",
    detail: "ECDH P-256 · AES-256-GCM · ECDSA",
    help: `
      <div class="prose"><p>Chaque personne tire un grand nombre secret ${M("d")} et publie le point ${M("Q = d·G")}
      de la courbe P-256. Retrouver ${M("d")} à partir de ${M("Q")} demanderait environ 2<sup>128</sup> opérations.</p></div>
      <div class="flow">
        <div class="stage" data-n="1"><h4>Chez l'expéditeur</h4><ul>
          <li>Calcule ${M("d_A · Q_B")} : le secret partagé.</li>
          <li>En dérive une clé AES-256 (HKDF).</li>
          <li>Chiffre en AES-GCM, qui ajoute un tag d'intégrité.</li>
          <li>Peut signer en ECDSA pour prouver qu'il est l'auteur.</li></ul></div>
        <div class="stage net" data-n="2"><h4>Sur le réseau</h4><p>Eve voit les deux clés publiques et le chiffré. Le secret partagé, lui, n'a jamais circulé.</p></div>
        <div class="stage" data-n="3"><h4>Chez le destinataire</h4><ul>
          <li>Calcule ${M("d_B · Q_A")} : il obtient exactement le même point.</li>
          <li>Déchiffre et vérifie le tag. Un seul bit modifié, et le message est rejeté.</li>
          <li>Vérifie la signature ECDSA si elle est présente.</li></ul></div>
      </div>
      <div class="callout">Ouvrez « Clés » sur les deux postes et comparez le secret partagé : il est identique des deux côtés.</div>`,
  },
  elgamal: {
    code: "ELG",
    title: "El-Gamal",
    tagline: "Transmission sécurisée et signature numérique",
    detail: "Groupe de 2048 bits (RFC 3526) · implémenté à la main",
    help: `
      <div class="prose"><p>Tout le monde partage un nombre premier ${M("p")} de 2048 bits et ${M("g = 2")}.
      La clé privée est un nombre ${M("x")}, la clé publique ${M("y = gˣ mod p")}.</p></div>
      <div class="flow">
        <div class="stage" data-n="1"><h4>Chez l'expéditeur</h4><ul>
          <li>Signe : ${M("r = gᵏ mod p")} et ${M("s = (H(m) − x·r)·k⁻¹ mod (p−1)")}.</li>
          <li>Chiffre avec un nouveau hasard ${M("k'")} : ${M("c₁ = gᵏ' mod p")}, ${M("c₂ = m·yᵏ' mod p")}.</li></ul></div>
        <div class="stage net" data-n="2"><h4>Sur le réseau</h4><p>Eve voit ${M("(c₁, c₂)")} et ${M("(r, s)")}.
          Grâce au hasard, le même message envoyé deux fois donne deux chiffrés différents.</p></div>
        <div class="stage" data-n="3"><h4>Chez le destinataire</h4><ul>
          <li>Déchiffre : ${M("m = c₂ · (c₁ˣ)⁻¹ mod p")}.</li>
          <li>Vérifie : ${M("g^H(m) ≡ yʳ · rˢ (mod p)")}.</li></ul></div>
      </div>
      <div class="callout warn">El-Gamal seul ne détecte pas une modification : c'est la signature qui garantit l'intégrité.
      Et si l'on réutilise ${M("k")} pour deux signatures, on révèle sa clé privée. Pour le voir, activez « Même k », envoyez deux messages signés en clair, puis regardez la console d'Eve.</div>`,
  },
};
