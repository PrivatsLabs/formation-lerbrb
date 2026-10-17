/*
 * access-worker.js : Gestion de l'inscription, des accès Bunny Stream et de l'administration Firestore
 */

const MAX_DEVICES = 3;
const LINK_LIFETIME = 30 * 60; // 30 min (la page renouvelle les liens toutes les 20 min)

const LESSONS = [
  { n: 0,  module: "Introduction", title: "Prologue : bienvenue dans la formation", video: "" },
  { n: 1,  module: "Module 1 : les fondations", title: "Mon parcours : comment tout a commencé", video: "" },
  { n: 2,  module: "Module 1 : les fondations", title: "Comment fonctionnent les algorithmes", video: "" },
  { n: 3,  module: "Module 1 : les fondations", title: "Choisir sa niche et son positionnement", video: "" },
  { n: 4,  module: "Module 1 : les fondations", title: "Optimiser son profil", video: "" },
  { n: 5,  module: "Module 2 : créer du contenu qui explose", title: "Les 3 premières secondes : le hook", video: "" },
  { n: 6,  module: "Module 2 : créer du contenu qui explose", title: "Structurer une vidéo de réaction", video: "" },
  { n: 7,  module: "Module 2 : créer du contenu qui explose", title: "Trouver des idées et des vidéos à réagir", video: "" },
  { n: 8,  module: "Module 2 : créer du contenu qui explose", title: "Filmer et monter simplement", video: "" },
  { n: 9,  module: "Module 2 : créer du contenu qui explose", title: "Réagir sans se faire supprimer", video: "" },
  { n: 10, module: "Module 3 : croissance et visibilité", title: "La stratégie de publication", video: "" },
  { n: 11, module: "Module 3 : croissance et visibilité", title: "Faire travailler TikTok et Facebook ensemble", video: "" },
  { n: 12, module: "Module 3 : croissance et visibilité", title: "Engagement et communauté", video: "" },
  { n: 13, module: "Module 3 : croissance et visibilité", title: "Analyser ses statistiques", video: "" },
  { n: 14, module: "Module 4 : aller plus loin", title: "Crédibilité et vérification des sources", video: "" },
  { n: 15, module: "Module 4 : aller plus loin", title: "Les erreurs qui bloquent la croissance", video: "" },
  { n: 16, module: "Module 4 : aller plus loin", title: "Monétiser son audience", video: "" },
  { n: 17, module: "Module 4 : aller plus loin", title: "Ton plan d'action sur 30 jours", video: "" },
];

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));

function safeEqual(a, b) {
  a = String(a || ""); b = String(b || "");
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}


/* ---------- Accès Firestore par compte de service (les règles Firestore peuvent rester fermées) ---------- */
let _gtok = null;
const b64u = (x) => btoa(typeof x === "string" ? x : String.fromCharCode(...new Uint8Array(x))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
async function googleToken(env) {
  if (_gtok && _gtok.exp > Date.now() + 60000) return _gtok.v;
  if (!env.SA_EMAIL || !env.SA_PRIVATE_KEY) throw new Error("SA_EMAIL / SA_PRIVATE_KEY manquants");
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64u(JSON.stringify({ iss: env.SA_EMAIL, scope: "https://www.googleapis.com/auth/datastore", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const pem = String(env.SA_PRIVATE_KEY).replace(/\\n/g, "\n").replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const key = await crypto.subtle.importKey("pkcs8", Uint8Array.from(atob(pem), (c) => c.charCodeAt(0)), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(head + "." + claim));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: head + "." + claim + "." + b64u(sig) }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("jeton Google refusé");
  _gtok = { v: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return _gtok.v;
}
async function fsFetch(env, url, opts = {}) {
  const t = await googleToken(env);
  return fetch(url, { ...opts, headers: { ...(opts.headers || {}), Authorization: "Bearer " + t } });
}
/* Limite de requêtes par IP (nécessite un espace KV lié sous le nom LIMITS ; sans KV, pas de limite) */
async function limited(env, request, name, max, windowSec) {
  if (!env.LIMITS) return false;
  const ip = request.headers.get("CF-Connecting-IP") || "?";
  const k = "rl:" + name + ":" + ip + ":" + Math.floor(Date.now() / (windowSec * 1000));
  const n = Number((await env.LIMITS.get(k)) || 0);
  if (n >= max) return true;
  await env.LIMITS.put(k, String(n + 1), { expirationTtl: Math.max(60, windowSec * 2) });
  return false;
}
const TOO_MANY = { error: "Trop de tentatives, réessaie dans quelques minutes." };
const normPhone = (p) => String(p || "").replace(/\D/g, "").replace(/^00/, "");
// Clé de recherche : les 8 derniers chiffres, identique avec ou sans indicatif (+225, 00225…)
const phoneKey = (p) => normPhone(p).slice(-8);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const allowed = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
    const origin = request.headers.get("Origin") || "";
    const cors = {
      "Access-Control-Allow-Origin": allowed.includes(origin) ? origin : (allowed[0] || ""),
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device, X-Admin-Key",
      "Vary": "Origin",
    };
    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { ...cors, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
      });

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    try {
      const p = url.pathname;

      if (p === "/register" && request.method === "POST") {
        if (await limited(env, request, "reg", 10, 3600)) return json(TOO_MANY, 429);
      }
      if (p.startsWith("/admin/") && request.method === "POST") {
        if (await limited(env, request, "adm", 30, 600)) return json(TOO_MANY, 429);
      }
      if (p === "/register" && request.method === "POST") return json(...(await registerUser(request, env)));
      if (p === "/videos" && request.method === "GET") return json(...(await videos(request, env)));
      if (p === "/admin/migrate-phones" && request.method === "POST") return json(...(await migratePhones(request, env)));
      if (p === "/admin/update-access" && request.method === "POST") return json(...(await adminUpdateAccess(request, env)));

      return json({ error: "not found" }, 404);
    } catch (e) {
      console.log("erreur serveur:", e && e.message);
      return json({ error: "Erreur serveur, réessaie dans un instant." }, 500);
    }
  },
};

/* ---------- Inscription publique (Crée Auth + Firestore avec acces: false) ---------- */
async function registerUser(request, env) {
  const b = await request.json().catch(() => ({}));
  const name = String(b.name || "").trim();
  const email = String(b.email || "").trim().toLowerCase();
  const phone = normPhone(b.phone);
  const password = String(b.password || "");

  // Anti-spam 1 : champ piège rempli = robot (on fait semblant que tout va bien)
  if (String(b.website || "").trim()) return [{ ok: true, message: "Compte créé avec succès." }, 200];
  if (email.length > 120 || password.length > 100) return [{ error: "Informations invalides." }, 400];

  // Anti-spam 2 : Cloudflare Turnstile (actif dès que le secret TURNSTILE_SECRET est défini)
  if (env.TURNSTILE_SECRET) {
    const ts = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: String(b.turnstile || ""), remoteip: request.headers.get("CF-Connecting-IP") || "" }),
    }).then((r) => r.json()).catch(() => ({}));
    if (!ts.success) return [{ error: "Vérification anti-robot échouée, réessaie." }, 400];
  }

  if (!email || !/^[^@\s]+@[^@\s]+$/.test(email) || password.length < 6 || phone.length < 8 || name.length < 2 || name.length > 80) {
    return [{ error: "Informations invalides ou mot de passe trop court." }, 400];
  }

  // 1. Créer le compte dans Firebase Auth
  const authRes = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${env.FIREBASE_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, returnSecureToken: true }),
  });
  const authData = await authRes.json();
  if (!authRes.ok) {
    return [{ error: authData.error?.message || "Erreur lors de la création du compte." }, 400];
  }

  const uid = authData.localId;

  // 2. Créer le document dans Firestore avec acces: false
  const fsUrl = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/users/${uid}`;
  const fsBody = {
    fields: {
      name: { stringValue: name },
      email: { stringValue: email },
      phone: { stringValue: phone },
      phoneKey: { stringValue: phoneKey(phone) },
      acces: { booleanValue: false },
      devices: { arrayValue: { values: [] } },
      createdAt: { stringValue: new Date().toISOString() }
    }
  };

  const fsRes = await fsFetch(env, fsUrl, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(fsBody),
  });
  if (!fsRes.ok) {
    // On annule le compte Auth pour ne pas laisser un compte sans fiche
    await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:delete?key=${env.FIREBASE_API_KEY}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ idToken: authData.idToken }),
    }).catch(() => {});
    return [{ error: "Inscription impossible, réessaie dans un instant." }, 500];
  }

  return [{ ok: true, message: "Compte créé avec succès." }, 200];
}

/* ---------- Vérification des vidéos (Bunny Stream) ---------- */
async function verifyFirebaseToken(env, idToken) {
  const r = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${env.FIREBASE_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ idToken }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.users || !j.users.length) return null;
  return j.users[0];
}

async function getFirestoreUser(env, uid) {
  const url = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/users/${uid}`;
  const r = await fsFetch(env, url);
  if (!r.ok) return null;
  const j = await r.json().catch(() => ({}));
  if (!j.fields) return null;

  return {
    uid,
    acces: j.fields.acces?.booleanValue || false,
    devices: (j.fields.devices?.arrayValue?.values || []).map((v) => v.stringValue).filter(Boolean),
  };
}

async function updateFirestoreUserDevices(env, uid, devices) {
  const url = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/users/${uid}?updateMask.fieldPaths=devices`;
  await fsFetch(env, url, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      fields: { devices: { arrayValue: { values: devices.map((d) => ({ stringValue: d })) } } }
    }),
  });
}

async function videos(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const idToken = auth.replace(/^Bearer\s+/i, "").trim();
  if (!idToken) return [{ error: "no-access" }, 401];

  const fbUser = await verifyFirebaseToken(env, idToken);
  if (!fbUser) return [{ error: "invalid-token" }, 401];

  const user = await getFirestoreUser(env, fbUser.localId);
  // Si acces n'est pas true, on bloque l'accès
  if (!user || user.acces !== true) {
    return [{ error: "not-paid" }, 403];
  }

  const device = request.headers.get("X-Device") || "";
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(device)) return [{ error: "bad-device" }, 400];

  user.devices = user.devices || [];
  if (!user.devices.includes(device)) {
    if (user.devices.length >= MAX_DEVICES) return [{ error: "devices" }, 403];
    user.devices.push(device);
    await updateFirestoreUserDevices(env, fbUser.localId, user.devices);
  }

  const expires = Math.floor(Date.now() / 1000) + LINK_LIFETIME;
  const lessons = [];
  for (const l of LESSONS) {
    let u = null;
    if (l.video) {
      const t = await sha256(env.BUNNY_TOKEN_KEY + l.video + expires);
      u = "https://iframe.mediadelivery.net/embed/" + env.BUNNY_LIBRARY_ID + "/" + l.video + "?token=" + t + "&expires=" + expires;
    }
    lessons.push({ n: l.n, module: l.module, title: l.title, url: u });
  }
  return [{ lessons }, 200];
}

/* ---------- Admin : Chercher par numéro et modifier acces (true/false) ---------- */
function isAdmin(request, env) {
  const k = request.headers.get("X-Admin-Key") || "";
  return !!env.ADMIN_KEY && String(env.ADMIN_KEY).length >= 20 && safeEqual(k, env.ADMIN_KEY);
}

async function adminUpdateAccess(request, env) {
  if (!isAdmin(request, env)) return [{ error: "forbidden" }, 403];

  const b = await request.json().catch(() => ({}));
  const phone = normPhone(b.phone);
  const acces = b.acces === true; // true ou false

  if (phone.length < 8) return [{ error: "Numéro de téléphone invalide (8 chiffres minimum)." }, 400];

  // Requête structurée Firestore pour trouver le document par son champ 'phone'
  const queryUrl = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents:runQuery`;
  const queryBody = {
    structuredQuery: {
      from: [{ collectionId: "users" }],
      where: {
        fieldFilter: {
          field: { fieldPath: "phoneKey" },
          op: "EQUAL",
          value: { stringValue: phoneKey(phone) }
        }
      }
    }
  };

  const qr = await fsFetch(env, queryUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(queryBody)
  });
  const qj = await qr.json().catch(() => ([]));

  // Trouver le document correspondant dans le résultat
  let docName = null;
  for (const item of qj) {
    if (item.document && item.document.name) {
      docName = item.document.name; // Format: projects/.../databases/(default)/documents/users/{uid}
      break;
    }
  }

  if (!docName) {
    return [{ error: "Aucun client trouvé avec ce numéro de téléphone." }, 404];
  }

  // Mettre à jour le champ 'acces' (true ou false)
  const patchUrl = `https://firestore.googleapis.com/v1/${docName}?updateMask.fieldPaths=acces`;
  const patchRes = await fsFetch(env, patchUrl, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      fields: {
        acces: { booleanValue: acces }
      }
    })
  });

  if (!patchRes.ok) {
    return [{ error: "Erreur lors de la mise à jour de l'accès dans Firestore." }, 500];
  }

  return [{ ok: true, message: acces ? "Accès autorisé." : "Accès bloqué." }, 200];
}

/* ---------- Migration unique : ajoute phoneKey aux clients déjà inscrits ---------- */
/* Appelle-la une seule fois (bouton dans admin.html), puis tu peux supprimer cette fonction et sa route. */
async function migratePhones(request, env) {
  if (!isAdmin(request, env)) return [{ error: "forbidden" }, 403];
  const base = `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
  const qr = await fsFetch(env, base + ":runQuery", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ structuredQuery: { from: [{ collectionId: "users" }] } }),
  });
  const rows = await qr.json().catch(() => []);
  let done = 0, skipped = 0;
  for (const it of rows) {
    const d = it.document;
    if (!d) continue;
    const raw = d.fields && d.fields.phone && d.fields.phone.stringValue;
    const key = phoneKey(raw);
    if (key.length < 8) { skipped++; continue; }
    const r = await fsFetch(env, `https://firestore.googleapis.com/v1/${d.name}?updateMask.fieldPaths=phoneKey&updateMask.fieldPaths=phone`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fields: { phoneKey: { stringValue: key }, phone: { stringValue: normPhone(raw) } } }),
    });
    if (r.ok) done++; else skipped++;
  }
  return [{ ok: true, message: `${done} client(s) mis à jour, ${skipped} ignoré(s).` }, 200];
}