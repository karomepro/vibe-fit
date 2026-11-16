// Vibe Fit sign-up: creates a confirmed Supabase Auth user and its account row in one step.
// Accounts are username + password only, so the login e-mail is derived from the username
// (the same way the site derives it) and never receives mail.
import { createClient } from "npm:@supabase/supabase-js@2.118.0";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const EMAIL_DOMAIN = "users.vibefit.invalid";

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });
}

// Same cyrb53 hash as the site, so account ids match what the page computes.
function cyrb53(str: string, seed = 0) {
  let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (let i = 0, ch; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
}
const accIdOf = (key: string) => "a" + cyrb53("acc|" + key, 5);

async function sha256hex(s: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
const emailOf = async (key: string) => "vf" + (await sha256hex("vibefit-user|" + key)).slice(0, 40) + "@" + EMAIL_DOMAIN;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json(405, { error: "method" });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json(400, { error: "bad_json" }); }

  const username = String(body?.username ?? "").trim().replace(/\s+/g, " ").slice(0, 30);
  const password = String(body?.password ?? "");
  if (!username) return json(400, { error: "name" });
  if (password.length < 20 || password.length > 72) return json(400, { error: "password" });
  const key = username.toLowerCase();

  const profile = body.profile && typeof body.profile === "object" && !Array.isArray(body.profile) ? body.profile : {};
  const pages = Array.isArray(body.pages) ? body.pages : [];
  if (JSON.stringify(profile).length > 15000 || JSON.stringify(pages).length > 300000) return json(400, { error: "too_big" });

  const url = Deno.env.get("SUPABASE_URL")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });

  const { data: existing, error: e0 } = await admin.from("accounts").select("id").eq("key", key).maybeSingle();
  if (e0) { console.error("lookup", e0); return json(500, { error: "db" }); }
  if (existing) return json(409, { error: "taken" });

  const { data: created, error: e1 } = await admin.auth.admin.createUser({
    email: await emailOf(key),
    password,
    email_confirm: true,
    user_metadata: { username },
  });
  if (e1 || !created?.user) {
    console.error("createUser", e1);
    if (e1 && (e1.status === 422 || /already|exists|registered/i.test(e1.message))) return json(409, { error: "taken" });
    return json(500, { error: "auth" });
  }

  const acc = accIdOf(key);
  const { error: e2 } = await admin.from("accounts").insert({
    id: acc, user_id: created.user.id, key, username, created_at: Date.now(), profile, pages,
  });
  if (e2) {
    console.error("insert", e2);
    await admin.auth.admin.deleteUser(created.user.id);
    return json(e2.code === "23505" ? 409 : 500, { error: e2.code === "23505" ? "taken" : "db" });
  }
  return json(200, { ok: true, acc });
});
