// routes/patreon.js — OAuth Patreon + liaison compte Supabase
//
// Routes exposées :
//   GET  /auth/patreon            → redirige vers patreon.com/oauth2/authorize
//   GET  /auth/patreon/callback   → échange code → tokens Patreon → identity
//                                   → crée/trouve user Supabase via Admin API
//                                   → upsert patreon_connections
//                                   → redirige via magic link (session auto) ou direct
//   GET  /auth/patreon/status     → connexion Patreon du user connecté (JWT requis)
//   DELETE /auth/patreon          → supprime la connexion (JWT requis)
//
// Deux chemins dans le callback :
//   A) Utilisateur PAS connecté à Supabase
//      → Admin API crée/trouve le user Supabase par email Patreon
//      → génère un magic link → redirige dessus → Supabase redirige vers frontend
//        avec #access_token=... dans le hash → session auto côté frontend
//   B) Utilisateur déjà connecté à Supabase (token passé dans ?token=)
//      → valide le JWT → lie Patreon à l'user existant → redirige directement

const express = require("express");
const axios   = require("axios");
const crypto  = require("crypto");
const router  = express.Router();
const { authenticate } = require("../common/core.js");

// ─── Config ──────────────────────────────────────────────────────────────────

const cfg = {
  clientId:        () => process.env.PATREON_CLIENT_ID      || "",
  clientSecret:    () => process.env.PATREON_CLIENT_SECRET  || "",
  redirectUri:     () => process.env.PATREON_REDIRECT_URI   || "http://localhost:2000/auth/patreon/callback",
  frontendBase:    () => process.env.PATREON_FRONTEND_REDIRECT || "http://localhost:2000/",
  supabaseUrl:     () => process.env.SUPABASE_URL_DEV || process.env.SUPABASE_URL || process.env.SUPABASE_URL_PROD || "",
  serviceKey:      () => process.env.SUPABASE_SERVICE_KEY || "",
};

// ─── CSRF state (mémoire, TTL 5 min) ─────────────────────────────────────────

const pendingStates = new Map();

function createState(supabaseToken) {
  const key = crypto.randomBytes(24).toString("hex");
  pendingStates.set(key, { supabaseToken: supabaseToken || null, createdAt: Date.now() });
  for (const [k, v] of pendingStates) {
    if (Date.now() - v.createdAt > 5 * 60 * 1000) pendingStates.delete(k);
  }
  return key;
}

function consumeState(key) {
  const entry = pendingStates.get(key);
  if (!entry) return null;
  pendingStates.delete(key);
  if (Date.now() - entry.createdAt > 5 * 60 * 1000) return null;
  return entry;
}

// ─── Helpers Supabase Admin API ───────────────────────────────────────────────

function adminHeaders() {
  const key = cfg.serviceKey();
  return {
    "apikey":        key,
    "Authorization": `Bearer ${key}`,
    "Content-Type":  "application/json",
  };
}

async function sbCreateOrFindUserAndGetMagicLink(email, redirectTo) {
  const url = `${cfg.supabaseUrl()}/auth/v1/admin/generate_link`;
  const r = await axios.post(url, {
    type:        "magiclink",
    email,
    redirect_to: redirectTo,
  }, { headers: adminHeaders(), timeout: 12000 });
  return {
    actionLink: r.data.action_link,
    userId:     r.data.user?.id || r.data.id || null,
  };
}

async function sbGetUserFromToken(token) {
  try {
    const r = await axios.get(`${cfg.supabaseUrl()}/auth/v1/user`, {
      headers: { "apikey": cfg.serviceKey(), "Authorization": `Bearer ${token}` },
      timeout: 8000,
    });
    return r.data || null;
  } catch {
    return null;
  }
}

async function sbUpsertPatreonConnection(data) {
  const url = `${cfg.supabaseUrl()}/rest/v1/patreon_connections?on_conflict=patreon_user_id`;
  const r = await axios.post(url, data, {
    headers: {
      ...adminHeaders(),
      "Prefer": "return=representation,resolution=merge-duplicates",
    },
    timeout: 10000,
  });
  return r.data;
}

async function sbGetPatreonConnection(userId) {
  const url = `${cfg.supabaseUrl()}/rest/v1/patreon_connections?user_id=eq.${userId}&select=*`;
  const r = await axios.get(url, { headers: adminHeaders(), timeout: 10000 });
  return r.data?.[0] || null;
}

async function sbDeletePatreonConnection(userId) {
  const url = `${cfg.supabaseUrl()}/rest/v1/patreon_connections?user_id=eq.${userId}`;
  await axios.delete(url, { headers: adminHeaders(), timeout: 10000 });
}

// ─── Helpers Patreon API ──────────────────────────────────────────────────────

async function patreonExchangeCode(code) {
  const r = await axios.post(
    "https://www.patreon.com/api/oauth2/token",
    new URLSearchParams({
      code,
      grant_type:    "authorization_code",
      client_id:     cfg.clientId(),
      client_secret: cfg.clientSecret(),
      redirect_uri:  cfg.redirectUri(),
    }).toString(),
    { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: 15000 }
  );
  return r.data; // { access_token, refresh_token, expires_in }
}

async function patreonGetIdentity(accessToken) {
  const params = [
    "include=memberships.campaign,memberships.currently_entitled_tiers",
    "fields[user]=email,full_name,image_url",
    "fields[member]=patron_status,currently_entitled_amount_cents",
    "fields[campaign]=creation_name,url",
    "fields[tier]=title,amount_cents",
  ].join("&");

  const r = await axios.get(
    `https://www.patreon.com/api/oauth2/v2/identity?${params}`,
    { headers: { "Authorization": `Bearer ${accessToken}` }, timeout: 15000 }
  );
  return r.data;
}

function parseMemberships(identity) {
  const included   = identity.included || [];
  const memberMap  = {}, campaignMap = {}, tierMap = {};

  for (const item of included) {
    if (item.type === "member")   memberMap[item.id]   = item;
    if (item.type === "campaign") campaignMap[item.id] = item;
    if (item.type === "tier")     tierMap[item.id]     = item;
  }

  return (identity.data?.relationships?.memberships?.data || []).map(ref => {
    const member   = memberMap[ref.id]  || {};
    const campRef  = member.relationships?.campaign?.data;
    const campaign = campRef ? (campaignMap[campRef.id] || {}) : {};
    const tiers    = (member.relationships?.currently_entitled_tiers?.data || []).map(t => {
      const tier = tierMap[t.id] || {};
      return { tier_id: t.id, tier_title: tier.attributes?.title || "", amount_cents: tier.attributes?.amount_cents || 0 };
    });
    return {
      campaign_id:   campRef?.id || null,
      campaign_name: campaign.attributes?.creation_name || "",
      campaign_url:  campaign.attributes?.url || "",
      patron_status: member.attributes?.patron_status || null,
      amount_cents:  member.attributes?.currently_entitled_amount_cents || 0,
      tiers,
    };
  });
}

function redirectError(res, msg) {
  return res.redirect(`${cfg.frontendBase()}?patreon_error=${encodeURIComponent(msg)}`);
}

// ─── Routes ──────────────────────────────────────────────────────────────────

// GET /auth/patreon
router.get("/auth/patreon", (req, res) => {
  if (!cfg.clientId()) return res.status(503).json({ error: "PATREON_CLIENT_ID non configuré" });

  const supabaseToken = req.query.token || null;
  const state = createState(supabaseToken);

  const params = new URLSearchParams({
    response_type: "code",
    client_id:     cfg.clientId(),
    redirect_uri:  cfg.redirectUri(),
    scope:         "identity identity[email] identity.memberships",
    state,
  });
  res.redirect(`https://www.patreon.com/oauth2/authorize?${params}`);
});

// GET /auth/patreon/callback
router.get("/auth/patreon/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error)           return redirectError(res, error);
  if (!code || !state) return redirectError(res, "missing_params");

  const stateEntry = consumeState(state);
  if (!stateEntry)     return redirectError(res, "invalid_or_expired_state");

  try {
    const tokens = await patreonExchangeCode(code);

    const identity    = await patreonGetIdentity(tokens.access_token);
    const patreonId   = identity.data?.id;
    const attrs       = identity.data?.attributes || {};
    const memberships = parseMemberships(identity);
    const expiresAt   = tokens.expires_in
      ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
      : null;

    const connectionPayload = {
      patreon_user_id:   patreonId,
      patreon_email:     attrs.email       || null,
      patreon_name:      attrs.full_name   || null,
      patreon_image_url: attrs.image_url   || null,
      access_token:      tokens.access_token,
      refresh_token:     tokens.refresh_token || null,
      token_expires_at:  expiresAt,
      raw_memberships:   memberships,
      updatedat:         new Date().toISOString(),
    };

    // ── Chemin B : user déjà connecté à Supabase ─────────────────────────────
    if (stateEntry.supabaseToken) {
      const sbUser = await sbGetUserFromToken(stateEntry.supabaseToken);
      if (!sbUser?.id) return redirectError(res, "invalid_supabase_token");

      await sbUpsertPatreonConnection({ user_id: sbUser.id, ...connectionPayload });
      return res.redirect(`${cfg.frontendBase()}?patreon_connected=1`);
    }

    // ── Chemin A : pas de session Supabase ───────────────────────────────────
    if (!attrs.email) return redirectError(res, "patreon_email_required");

    const base = cfg.frontendBase().replace(/\/?$/, '/');
    const { actionLink, userId } = await sbCreateOrFindUserAndGetMagicLink(
      attrs.email,
      base + 'login.html'
    );
    if (!userId) return redirectError(res, "supabase_user_creation_failed");

    await sbUpsertPatreonConnection({ user_id: userId, ...connectionPayload });
    res.redirect(actionLink);

  } catch (err) {
    console.error("[patreon callback]", err.response?.data || err.message);
    redirectError(res, err.message);
  }
});

// GET /auth/patreon/status  (JWT requis)
router.get("/auth/patreon/status", authenticate, async (req, res) => {
  try {
    const conn = await sbGetPatreonConnection(req.user.id);
    if (!conn) return res.json({ connected: false });
    const { access_token, refresh_token, ...safe } = conn;
    res.json({ connected: true, connection: safe });
  } catch (err) {
    console.error("[patreon status]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /auth/patreon  (JWT requis)
router.delete("/auth/patreon", authenticate, async (req, res) => {
  try {
    await sbDeletePatreonConnection(req.user.id);
    res.json({ ok: true });
  } catch (err) {
    console.error("[patreon delete]", err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
