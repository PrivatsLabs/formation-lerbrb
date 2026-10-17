/*
 * stats-worker.js : petit serveur qui donne à ta page de vente
 *   - le nombre d'abonnés de ta page Facebook et de ton compte TikTok
 *   - le pays du visiteur (pour afficher le bon drapeau)
 *
 * POURQUOI UN SERVEUR ? Tes clés d'accès (tokens) ne doivent JAMAIS être
 * écrites dans la page : n'importe qui pourrait les copier et prendre le
 * contrôle de tes comptes. Elles restent ici, côté serveur.
 *
 * INSTALLATION (compte Cloudflare gratuit) :
 *  1. Cloudflare > Workers & Pages > Create > Worker. Colle ce code, Deploy.
 *  2. Workers > KV > crée un espace nommé TOKENS, puis dans ton Worker :
 *     Settings > Bindings > KV namespace, nom de variable : TOKENS.
 *  3. Settings > Variables and Secrets, ajoute (en "Secret" pour les clés) :
 *       ALLOWED_ORIGIN       l'adresse de ton site, ex : https://monsite.com
 *       FB_PAGE_ID           l'identifiant de ta PAGE Facebook
 *       FB_PAGE_TOKEN        jeton d'accès de la Page (secret)
 *       GRAPH_VERSION        (facultatif) ex : v23.0 - vérifie la version actuelle chez Meta
 *       TIKTOK_CLIENT_KEY    clé de ton app sur developers.tiktok.com
 *       TIKTOK_CLIENT_SECRET secret de ton app (secret)
 *       TIKTOK_REFRESH_TOKEN jeton de renouvellement obtenu après autorisation (secret)
 *  4. Copie l'adresse du Worker (https://xxx.workers.dev) dans
 *     CONFIG.statsEndpoint de index.html.
 *
 * LIMITES A CONNAITRE :
 *  - Facebook : ça marche pour une PAGE Facebook, pas pour un profil personnel.
 *  - TikTok : il faut une app créée sur developers.tiktok.com avec Login Kit
 *    et Display API, avec les autorisations "user.info.stats" (abonnés) et
 *    "user.info.basic" (photo de profil et nom), à accorder avec TON compte TikTok
 *    (@lerbrb1) lors de l'autorisation. Sans l'approbation de TikTok, la page
 *    garde le chiffre de secours et la lettre à la place de la photo.
 *  - La photo est servie par ce Worker (adresse /avatar) car le lien de TikTok expire.
 *  - Chaque service est indépendant : si l'un échoue, l'autre s'affiche quand même.
 *  - Les chiffres sont mis en cache 10 minutes pour ne pas dépasser les limites.
 */

const CACHE_SECONDS = 600;

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
    const corsOrigin = allowed.includes(origin) ? origin : (allowed[0] || "");

    const headers = {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": corsOrigin,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Vary": "Origin",
      "Cache-Control": "no-store",
    };

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (request.method !== "GET") return new Response("Method not allowed", { status: 405, headers });

    const url = new URL(request.url);

    // Photo de profil TikTok, relayée par le Worker
    if (url.pathname === "/avatar") {
      const st = await getStats(env, ctx);
      const src = st.profile && st.profile.avatarUrl;
      if (!src || !/^https:\/\//.test(src)) return new Response("Not found", { status: 404 });
      const up = await fetch(src);
      if (!up.ok) return new Response("Unavailable", { status: 502 });
      return new Response(up.body, {
        headers: { "Content-Type": up.headers.get("Content-Type") || "image/jpeg", "Cache-Control": "public, max-age=3600" },
      });
    }

    const country = (request.cf && request.cf.country) || null; // pays déduit par Cloudflare
    const stats = await getStats(env, ctx);
    const { profile, ...pub } = stats;
    const out = {
      country,
      ...pub,
      name: (profile && profile.name) || null,
      avatar: profile && profile.avatarUrl ? url.origin + "/avatar" : null,
    };

    return new Response(JSON.stringify(out), { headers });
  },
};

async function getStats(env, ctx) {
  const cache = caches.default;
  const key = new Request("https://stats.cache.internal/v1");
  const hit = await cache.match(key);
  if (hit) return hit.json();

  const [facebook, tiktok] = await Promise.all([
    getFacebook(env).catch((e) => { console.log("facebook:", e.message); return null; }),
    getTikTok(env).catch((e) => { console.log("tiktok:", e.message); return null; }),
  ]);

  const data = {
    facebook,
    tiktok: tiktok ? tiktok.followers : null,
    profile: tiktok ? { name: tiktok.name, avatarUrl: tiktok.avatarUrl } : null,
    updated: new Date().toISOString(),
  };

  if (facebook || tiktok) {
    const res = new Response(JSON.stringify(data), {
      headers: { "Cache-Control": "max-age=" + CACHE_SECONDS },
    });
    ctx.waitUntil(cache.put(key, res));
  }
  return data;
}

/* ---------- Facebook (Graph API, Page) ---------- */
async function getFacebook(env) {
  if (!env.FB_PAGE_ID || !env.FB_PAGE_TOKEN) return null;
  const v = env.GRAPH_VERSION || "v23.0";
  const url =
    "https://graph.facebook.com/" + v + "/" + encodeURIComponent(env.FB_PAGE_ID) +
    "?fields=followers_count,fan_count&access_token=" + encodeURIComponent(env.FB_PAGE_TOKEN);
  const r = await fetch(url);
  const j = await r.json();
  if (!r.ok) throw new Error((j.error && j.error.message) || "graph error " + r.status);
  return j.followers_count || j.fan_count || null;
}

/* ---------- TikTok (Display API, scope user.info.stats) ---------- */
async function getTikTok(env) {
  if (!env.TIKTOK_CLIENT_KEY || !env.TIKTOK_CLIENT_SECRET) return null;
  if (!env.TOKENS) throw new Error("KV TOKENS non lié");

  let access = await env.TOKENS.get("tt_access");
  const exp = Number((await env.TOKENS.get("tt_exp")) || 0);
  if (!access || Date.now() > exp - 60000) access = await refreshTikTok(env);

  const ALL = "display_name,avatar_url,avatar_large_url,follower_count";
  let j = await tiktokInfo(access, ALL);
  if (j.status === 401) {
    access = await refreshTikTok(env);
    j = await tiktokInfo(access, ALL);
  }
  let u = j.body && j.body.data && j.body.data.user;
  if (!u || typeof u.follower_count !== "number") {
    // Photo/nom non autorisés (user.info.basic) : on retente avec les abonnés seuls
    j = await tiktokInfo(access, "follower_count");
    u = j.body && j.body.data && j.body.data.user;
  }
  if (!u || typeof u.follower_count !== "number") throw new Error("follower_count absent (scope user.info.stats approuvé ?)");
  return { followers: u.follower_count, name: u.display_name || null, avatarUrl: u.avatar_large_url || u.avatar_url || null };
}

async function tiktokInfo(access, fields) {
  const r = await fetch("https://open.tiktokapis.com/v2/user/info/?fields=" + fields, {
    headers: { Authorization: "Bearer " + access },
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

async function refreshTikTok(env) {
  const refresh = (await env.TOKENS.get("tt_refresh")) || env.TIKTOK_REFRESH_TOKEN;
  if (!refresh) throw new Error("refresh token manquant");
  const r = await fetch("https://open.tiktokapis.com/v2/oauth/token/", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_key: env.TIKTOK_CLIENT_KEY,
      client_secret: env.TIKTOK_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: refresh,
    }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("renouvellement TikTok refusé");
  await env.TOKENS.put("tt_access", j.access_token);
  await env.TOKENS.put("tt_exp", String(Date.now() + (j.expires_in || 86400) * 1000));
  if (j.refresh_token) await env.TOKENS.put("tt_refresh", j.refresh_token);
  return j.access_token;
}