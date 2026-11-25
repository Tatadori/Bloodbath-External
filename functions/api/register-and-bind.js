function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(saltHex), iterations: 100000, hash: "SHA-256" },
    keyMat,
    256
  );
  return `${saltHex}:${toHex(bits)}`;
}

export async function onRequestPost({ request, env }) {
  const json = (body, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

  const { username, password, license_key } = await request.json().catch(() => ({}));
  if (!username || !password || !license_key) {
    return json({ ok: false, message: "Username, password, and license key are required." }, 400);
  }

  const headers = {
    "apikey": env.SUPABASE_SERVICE_ROLE_KEY,
    "Authorization": `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
  };

  // 1. Check if license key exists and is unbound
  const licRes = await fetch(
    `${env.SUPABASE_URL}/rest/v1/licenses?key_code=eq.${encodeURIComponent(license_key)}&select=key_code,bound_username,status`,
    { headers }
  );
  const licRows = await licRes.json();
  if (!Array.isArray(licRows) || licRows.length === 0) {
    return json({ ok: false, message: "Unknown license key." }, 404);
  }
  if (licRows[0].bound_username) {
    return json({ ok: false, message: "That license key is already bound to an account." }, 409);
  }

  // 2. Create user
  const salt = crypto.randomUUID().replace(/-/g, "");
  const password_hash = await hashPassword(password, salt);
  const userRes = await fetch(`${env.SUPABASE_URL}/rest/v1/users`, {
    method: "POST",
    headers: { ...headers, "Prefer": "return=representation" },
    body: JSON.stringify({ username, password_hash }),
  });
  if (!userRes.ok) {
    return json({ ok: false, message: "Username already taken." }, 409);
  }

  // 3. Bind license key to username
  await fetch(`${env.SUPABASE_URL}/rest/v1/licenses?key_code=eq.${encodeURIComponent(license_key)}`, {
    method: "PATCH",
    headers,
    body: JSON.stringify({ bound_username: username, status: "active", bound_at: new Date().toISOString() }),
  });

  return json({ ok: true, username, message: "Account created and key bound." });
}
