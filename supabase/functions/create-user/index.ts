import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { ...corsHeaders, "Content-Type": "application/json" },
});

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ success: false, error: "Method not allowed." }, 405);

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return json({ success: false, error: "Authentication required." }, 401);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !anonKey || !serviceRoleKey) {
      return json({ success: false, error: "Server configuration is incomplete." }, 500);
    }

    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: { user: caller }, error: callerError } = await authClient.auth.getUser(
      authHeader.slice("Bearer ".length).trim(),
    );
    if (callerError || !caller) {
      return json({ success: false, error: "Invalid or expired login session." }, 401);
    }

    const adminClient = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: callerProfile, error: profileError } = await adminClient
      .from("user_profiles").select("id,role,active").eq("id", caller.id).single();
    if (profileError || !callerProfile || callerProfile.active !== true || callerProfile.role !== "Admin") {
      return json({ success: false, error: "Administrator permission is required." }, 403);
    }

    const body = await req.json();
    const fullName = String(body.full_name ?? "").trim();
    const username = String(body.username ?? "").trim().toLowerCase();
    const password = String(body.password ?? "");
    const role = String(body.role ?? "").trim();
    const submittedHQIds = Array.isArray(body.hq_ids)
      ? body.hq_ids
      : (body.hq_id ? [body.hq_id] : []);
    const hqIds = [...new Set(submittedHQIds.map((value: unknown) => String(value).trim()).filter(Boolean))];

    if (!fullName) return json({ success: false, error: "Full name is required." }, 400);
    if (!/^[a-z0-9._-]+$/.test(username)) {
      return json({
        success: false,
        error: "Username can contain only letters, numbers, dot, underscore and hyphen.",
      }, 400);
    }
    if (password.length < 6) {
      return json({ success: false, error: "Password must contain at least 6 characters." }, 400);
    }
    if (!["Admin", "ABM", "Field Staff"].includes(role)) {
      return json({ success: false, error: "Invalid role." }, 400);
    }
    if (!hqIds.length) return json({ success: false, error: "Select at least one HQ." }, 400);
    if (role === "Field Staff" && hqIds.length !== 1) {
      return json({ success: false, error: "Field Staff must have exactly one assigned HQ." }, 400);
    }

    const { data: hqs, error: hqError } = await adminClient
      .from("hqs").select("id").in("id", hqIds).eq("active", true);
    if (hqError || (hqs || []).length !== hqIds.length) {
      return json({ success: false, error: "One or more selected HQs are invalid or inactive." }, 400);
    }

    const email = `${username}@hexadox-mis.local`;
    const { data: created, error: createError } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { username, full_name: fullName },
    });
    if (createError || !created.user) {
      return json({ success: false, error: createError?.message || "Unable to create Auth user." }, 400);
    }

    const newUserId = created.user.id;
    const { error: insertProfileError } = await adminClient.from("user_profiles").insert({
      id: newUserId,
      full_name: fullName,
      role,
      active: true,
    });
    if (insertProfileError) {
      await adminClient.auth.admin.deleteUser(newUserId);
      return json({ success: false, error: "User profile could not be created." }, 500);
    }

    const { error: mappingError } = await adminClient.from("user_hq_mapping").insert(
      hqIds.map((hq_id) => ({ user_id: newUserId, hq_id })),
    );
    if (mappingError) {
      await adminClient.from("user_profiles").delete().eq("id", newUserId);
      await adminClient.auth.admin.deleteUser(newUserId);
      return json({ success: false, error: "User-HQ mappings could not be created." }, 500);
    }

    return json({ success: true, user_id: newUserId, assigned_hqs: hqIds.length });
  } catch (error) {
    console.error("CREATE USER ERROR:", error);
    return json({
      success: false,
      error: error instanceof Error ? error.message : "Unexpected server error.",
    }, 500);
  }
});
