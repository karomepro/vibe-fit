// Vibe Fit AI meal calculator: a photo and/or a description → calories and macros, estimated by Gemini.
// The Gemini key lives in the project's Edge Function secrets (GEMINI_API_KEY) and never reaches the page.
// Only signed-in members can call it, with a daily cap per person.
import { createClient } from "npm:@supabase/supabase-js@2.118.0";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const DAILY = 40;                                    // analyses per person per day (per running instance)
const used = new Map<string, number>();
const MODELS = [Deno.env.get("GEMINI_MODEL"), "gemini-3.8-flash", "gemini-flash-latest", "gemini-3.6-flash"]
  .filter((m, i, a): m is string => !!m && a.indexOf(m) === i);

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });
}

function prompt(desc: string, hasImage: boolean) {
  return `أنت أخصائي تغذية خبير في الأكل الخليجي والعربي والعالمي. ${hasImage ? "حلّل صورة الوجبة المرفقة" : "حلّل وصف الوجبة التالي"} وقدّر السعرات الحرارية والبروتين والكربوهيدرات والدهون لكل مكوّن حسب الكمية ${hasImage ? "الظاهرة في الصورة (استدل بحجم الصحن والأدوات)" : "الموصوفة (إذا لم تُذكر الكمية افترض حصة شخص واحد متوسطة)"}.
${desc ? `ملاحظة المستخدم: """${desc.replace(/"""/g, '"')}"""\n` : ""}القواعد:
- استخدم قيماً غذائية معتمدة، وقرّب الأرقام لأقرب عدد صحيح.
- اكتب أسماء المكوّنات والحصص بالعربية بشكل مختصر وواضح.
- لا تكرر المكوّن نفسه، وادمج الصلصات الصغيرة مع الطبق.
- إذا لم يكن في الصورة أو الوصف طعام يمكن تقديره فأعد: {"not_food": true, "reason": "سبب قصير"}
أعد JSON فقط بهذا الشكل بدون أي نص قبله أو بعده:
{"title": "اسم مختصر للوجبة", "items": [{"name": "رز أبيض", "portion": "كوب ونصف", "grams": 240, "kcal": 310, "protein": 6, "carbs": 68, "fat": 1}], "confidence": "high", "tip": "نصيحة قصيرة جداً تخص هذه الوجبة"}
قيمة confidence واحدة من: high أو medium أو low.`;
}

function parseJson(text: string) {
  try { return JSON.parse(text); } catch { /* try the outermost braces */ }
  const a = text.indexOf("{"), b = text.lastIndexOf("}");
  if (a >= 0 && b > a) { try { return JSON.parse(text.slice(a, b + 1)); } catch { /* fall through */ } }
  return null;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json(405, { error: "method" });

  // who is asking: a signed-in Vibe Fit member
  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false, autoRefreshToken: false } });
  const { data: who, error: authErr } = token ? await admin.auth.getUser(token) : { data: null, error: true };
  if (authErr || !who?.user) return json(401, { error: "auth" });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json(400, { error: "bad_json" }); }
  const key = Deno.env.get("GEMINI_API_KEY") || "";
  if (body.probe) return json(200, { ok: true, configured: !!key });
  if (!key) return json(503, { error: "not_configured" });

  const desc = String(body.desc ?? "").trim().slice(0, 400);
  const image = typeof body.image === "string" ? body.image : "";
  const mime = ["image/jpeg", "image/png", "image/webp"].includes(String(body.mime)) ? String(body.mime) : "image/jpeg";
  if (!desc && !image) return json(400, { error: "empty" });
  if (image.length > 6_000_000) return json(413, { error: "bad_image" });

  const day = new Date().toISOString().slice(0, 10), slot = `${who.user.id}|${day}`;
  const n = used.get(slot) || 0;
  if (n >= DAILY) return json(429, { error: "daily_limit" });
  used.set(slot, n + 1);

  const parts: Record<string, unknown>[] = [{ text: prompt(desc, !!image) }];
  if (image) parts.push({ inline_data: { mime_type: mime, data: image } });
  const payload = JSON.stringify({ contents: [{ role: "user", parts }], generationConfig: { responseMimeType: "application/json", temperature: 0.2 } });

  for (const model of MODELS) {
    let r: Response;
    try {
      r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: "POST", headers: { "Content-Type": "application/json", "x-goog-api-key": key }, body: payload,
      });
    } catch (e) {
      console.error("fetch", model, String(e));
      return json(502, { error: "upstream" });
    }
    if (r.status === 404) { console.error("model not found", model); continue; }       // try the next model name
    const j = await r.json().catch(() => ({}));
    const msg = String(j?.error?.message || "");
    if (r.status === 429) return json(429, { error: "rate_limited" });
    if ((r.status === 400 || r.status === 403) && /api key|API_KEY|permission/i.test(msg)) { console.error("key", r.status, msg); return json(503, { error: "bad_key" }); }
    if (r.status === 400 && /image|inline|mime|base64/i.test(msg)) return json(400, { error: "bad_image" });
    if (!r.ok) { console.error("gemini", model, r.status, msg); return json(502, { error: "upstream", status: r.status }); }
    if (j?.promptFeedback?.blockReason) return json(422, { error: "refused" });
    const cand = j?.candidates?.[0];
    const text = (cand?.content?.parts || []).map((p: { text?: string }) => p.text || "").join("");
    if (!text) return json(422, { error: cand?.finishReason === "SAFETY" ? "refused" : "empty" });
    const result = parseJson(text);
    if (!result || typeof result !== "object") return json(502, { error: "invalid_json" });
    return json(200, { ok: true, model, result });
  }
  return json(502, { error: "no_model" });
});
