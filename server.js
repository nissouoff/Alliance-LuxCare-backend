import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import multer from "multer";
import { createClient } from "@supabase/supabase-js";
import { createServer } from "http";
import { Server } from "socket.io";

const {
  PORT = 5000,
  NODE_ENV = "development",
  FRONTEND_URL = "http://localhost:3000",
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  ALLOWED_ADMIN_IPS = "",
} = process.env;

for (const key of ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]) {
  if (!process.env[key]) {
    console.error(`[FATAL] Missing env: ${key}`);
    process.exit(1);
  }
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

const app = express();

app.use(helmet());
app.set("trust proxy", true);

const rawOrigins = FRONTEND_URL || "";
const allowedOrigins = rawOrigins.split(",").map((url) => url.trim()).filter(Boolean);

if (!allowedOrigins.includes("http://localhost:3000")) {
  allowedOrigins.push("http://localhost:3000");
}

console.log("[CORS Configuration] Allowed Origins:", allowedOrigins);

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.error(`[CORS Blocked] Origin: ${origin} is not present in allowed list.`);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With", "Accept"],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.use(express.json({ limit: "1mb" }));

const server = createServer(app);

const io = new Server(server, {
  cors: {
    origin: allowedOrigins,
    credentials: true,
  },
});

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) {
      return next(new Error("Auth token required"));
    }

    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data?.user) {
      return next(new Error("Invalid or expired token"));
    }

    socket.data.user = data.user;

    const { data: profile } = await supabase
      .from("profiles")
      .select("role")
      .eq("id", data.user.id)
      .single();

    socket.data.role = profile?.role || "client";

    next();
  } catch (err) {
    next(new Error("Auth failed"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.data.user.id;
  const role = socket.data.role;

  socket.join(userId);
  console.log(`[SOCKET] User ${userId} connected (role: ${role})`);

  if (role === "admin") {
    socket.join("admin");
    console.log(`[SOCKET] Admin ${userId} joined admin room`);
  }

  socket.on("disconnect", () => {
    console.log(`[SOCKET] User ${userId} disconnected`);
  });
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed = ["application/pdf", "image/jpeg", "image/png"];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new multer.MulterError("LIMIT_UNEXPECTED_FILE", file.fieldname));
    }
  },
});

// ─── Helpers ───────────────────────────────────────────

function mapUrgency(value) {
  if (value === "Immédiat / Critique") return "critical";
  if (value === "Urgent") return "high";
  return "low";
}

function parseConsent(value) {
  if (value === true || value === "true") return true;
  return false;
}

async function uploadToStorage(buffer, mimetype, userId, originalName) {
  const ext = originalName.split(".").pop() || "bin";
  const path = `${userId}/${Date.now()}-${Math.random().toString(36).slice(2, 8)}.${ext}`;

  const { error: uploadErr } = await supabase.storage
    .from("medical-documents")
    .upload(path, buffer, { contentType: mimetype, upsert: false });

  if (uploadErr) throw new Error(uploadErr.message);

  const { data: pub } = supabase.storage.from("medical-documents").getPublicUrl(path);
  if (pub?.publicUrl) return pub.publicUrl;

  const { data: signed, error: signErr } = await supabase.storage
    .from("medical-documents")
    .createSignedUrl(path, 60 * 60 * 24 * 7);
  if (signErr) throw new Error(signErr.message);

  return signed.signedUrl;
}

function buildClientPayload(body) {
  return {
    full_name: body.fullName || null,
    phone: body.phone || null,
    residence_country: body.residenceCountry || null,
    location: body.pathwayCountry || null,
    request_nature: body.natureOfRequest || null,
    contact_type: body.contactType || null,
    urgency_level: mapUrgency(body.urgencyLevel),
    description: body.message || null,
    consent: parseConsent(body.consent),
  };
}

// ─── Auth Middleware ───────────────────────────────────
async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header?.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Token d'authentification manquant." });
    }

    const token = header.slice(7);
    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data?.user) {
      return res.status(401).json({ error: "Token invalide ou expiré." });
    }

    req.user = data.user;
    next();
  } catch (err) {
    console.error("[AUTH]", err.message);
    return res.status(401).json({ error: "Échec de l'authentification." });
  }
}

// ─── Client Guard ──────────────────────────────────────
async function requireClient(req, res, next) {
  try {
    const { data: profile } = await supabase
      .from("profiles")
      .select("role")
      .eq("id", req.user.id)
      .single();

    if (profile?.role === "admin") {
      console.error(`[CLIENT GUARD] Admin user ${req.user.id} blocked from client route ${req.originalUrl}`);
      return res.status(403).json({
        error: "Comptes administrateurs non autorisés sur cet endpoint client. Utilisez /api/admin/requests.",
      });
    }

    next();
  } catch (err) {
    console.error("[CLIENT GUARD]", err.message);
    return res.status(403).json({ error: "Accès refusé." });
  }
}

async function requireAdmin(req, res, next) {
  try {
    const clientIp = req.ip;
    const allowedIps = ALLOWED_ADMIN_IPS.split(",").map((s) => s.trim()).filter(Boolean);

    if (allowedIps.length > 0 && !allowedIps.includes(clientIp)) {
      console.error(`[ADMIN IP BLOCKED] IP ${clientIp} rejected`);
      console.log(`[IP Whitelist] Request from ${clientIp}, allowed: false`);
      return res.status(403).json({ error: "Accès refusé depuis cette adresse IP." });
    }

    console.log(`[IP Whitelist] Request from ${clientIp}, allowed: true`);

    const { data, error } = await supabase
      .from("profiles")
      .select("role")
      .eq("id", req.user.id)
      .single();

    if (error || data?.role !== "admin") {
      console.error("[ADMIN ROLE] User", req.user.id, "is not admin");
      return res.status(403).json({ error: "Privilèges administrateur requis." });
    }

    console.log(`[ADMIN OK] User ${req.user.id} from IP ${clientIp}`);
    next();
  } catch (err) {
    console.error("[ADMIN MIDDLEWARE]", err.message);
    return res.status(403).json({ error: "Échec de la vérification administrateur." });
  }
}

// ═══════════════════════════════════════════════════════
//  CLIENT ENDPOINTS
// ═══════════════════════════════════════════════════════

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", env: NODE_ENV, timestamp: new Date().toISOString() });
});

// ─── POST /api/requests ─ Create Request ──────────────
app.post("/api/requests", requireAuth, requireClient, upload.array("documents", 5), async (req, res) => {
  try {
    console.log("[POST /api/requests] Body:", req.body);
    console.log("[POST /api/requests] Files:", req.files);

    const payload = buildClientPayload(req.body);

    const missingFields = [];
    if (!payload.full_name) missingFields.push("fullName");
    if (!payload.phone) missingFields.push("phone");
    if (!payload.location) missingFields.push("pathwayCountry");
    if (!payload.request_nature) missingFields.push("natureOfRequest");
    if (!payload.contact_type) missingFields.push("contactType");
    if (!payload.description) missingFields.push("message");

    if (missingFields.length > 0) {
      console.error("[POST /api/requests] Missing fields:", missingFields.join(", "));
      return res.status(400).json({ error: `Champs manquants: ${missingFields.join(", ")}` });
    }

    if (!payload.consent) {
      return res.status(400).json({ error: "Le consentement est obligatoire." });
    }

    let documentUrls = [];
    if (req.files && req.files.length > 0) {
      const uploads = req.files.map((f) =>
        uploadToStorage(f.buffer, f.mimetype, req.user.id, f.originalname),
      );
      documentUrls = await Promise.all(uploads);
    }

    const insertPayload = {
      client_id: req.user.id,
      user_email: req.user.email,
      ...payload,
      documents: documentUrls.length > 0 ? documentUrls : null,
      status: "pending",
      current_step: 1,
    };

    const { data: request, error: dbError } = await supabase
      .from("requests")
      .insert(insertPayload)
      .select()
      .single();

    if (dbError) {
      console.error("[DB INSERT]", dbError.message);
      return res.status(500).json({ error: "Erreur lors de la création de la demande." });
    }

    io.to("admin").emit("request_created", request);
    console.log("[SOCKET] Emitted request_created to admin room");

    return res.status(201).json(request);
  } catch (err) {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({ error: "Fichier dépasse la limite de 10 Mo." });
      }
      return res.status(400).json({ error: `Erreur d'upload: ${err.message}` });
    }
    console.error("[POST /api/requests]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── GET /api/requests ─ List Requests ────────────────
app.get("/api/requests", requireAuth, requireClient, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("requests")
      .select("*")
      .eq("client_id", req.user.id)
      .order("created_at", { ascending: false });

    if (error) {
      console.error("[DB SELECT]", error.message);
      return res.status(500).json({ error: "Erreur lors de la récupération des demandes." });
    }

    return res.json(data);
  } catch (err) {
    console.error("[GET /api/requests]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── GET /api/requests/:id ─ Single Request ───────────
app.get("/api/requests/:id", requireAuth, requireClient, async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from("requests")
      .select("*")
      .eq("id", id)
      .single();

    if (error || !data) {
      console.error("[GET /api/requests/:id] Not found:", id);
      return res.status(404).json({ error: "Demande introuvable." });
    }

    if (data.client_id !== req.user.id) {
      return res.status(403).json({ error: "Accès refusé." });
    }

    return res.json(data);
  } catch (err) {
    console.error("[GET /api/requests/:id]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── PATCH /api/requests/:id ─ Edit Request ───────────
app.patch("/api/requests/:id", requireAuth, requireClient, upload.array("documents", 5), async (req, res) => {
  try {
    const { id } = req.params;

    console.log("[PATCH /api/requests/:id] Body:", req.body);
    console.log("[PATCH /api/requests/:id] Files:", req.files);

    const { data: existing, error: fetchErr } = await supabase
      .from("requests")
      .select("client_id, status")
      .eq("id", id)
      .single();

    if (fetchErr || !existing) {
      console.error("[PATCH] Not found:", id);
      return res.status(404).json({ error: "Demande introuvable." });
    }

    if (existing.client_id !== req.user.id) {
      return res.status(403).json({ error: "Accès refusé." });
    }

    if (existing.status !== "pending" && existing.status !== "cancelled") {
      console.error("[PATCH] Blocked: request", id, "has status", existing.status);
      return res.status(403).json({ error: "Impossible de modifier une demande déjà en cours de traitement" });
    }

    const payload = buildClientPayload(req.body);

    const updatePayload = {};
    for (const [key, value] of Object.entries(payload)) {
      if (value !== null && value !== undefined) {
        updatePayload[key] = value;
      }
    }

    if (req.files && req.files.length > 0) {
      const uploads = req.files.map((f) =>
        uploadToStorage(f.buffer, f.mimetype, req.user.id, f.originalname),
      );
      updatePayload.documents = await Promise.all(uploads);
    }

    if (Object.keys(updatePayload).length === 0) {
      return res.status(400).json({ error: "Aucun champ à mettre à jour." });
    }

    const { data: updated, error: updErr } = await supabase
      .from("requests")
      .update(updatePayload)
      .eq("id", id)
      .select()
      .single();

    if (updErr) {
      console.error("[PATCH]", updErr.message);
      return res.status(500).json({ error: "Erreur lors de la mise à jour." });
    }

    console.log("[PATCH] Request", id, "updated");
    return res.status(200).json(updated);
  } catch (err) {
    if (err instanceof multer.MulterError) {
      if (err.code === "LIMIT_FILE_SIZE") {
        return res.status(413).json({ error: "Fichier dépasse la limite de 10 Mo." });
      }
      return res.status(400).json({ error: `Erreur d'upload: ${err.message}` });
    }
    console.error("[PATCH /api/requests/:id]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── DELETE /api/requests/:id ─ Delete Request ─────────
app.delete("/api/requests/:id", requireAuth, requireClient, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: existing, error: fetchErr } = await supabase
      .from("requests")
      .select("client_id, status")
      .eq("id", id)
      .single();

    if (fetchErr || !existing) {
      console.error("[DELETE] Not found:", id);
      return res.status(404).json({ error: "Demande introuvable." });
    }

    if (existing.client_id !== req.user.id) {
      console.error("[DELETE] Unauthorized user", req.user.id, "for request", id);
      return res.status(403).json({ error: "Accès refusé." });
    }

    if (existing.status !== "pending" && existing.status !== "cancelled") {
      console.error("[DELETE] Blocked: request", id, "has status", existing.status);
      return res.status(403).json({ error: "Impossible de supprimer une demande déjà en cours de traitement" });
    }

    const { error: delErr } = await supabase
      .from("requests")
      .delete()
      .eq("id", id);

    if (delErr) {
      console.error("[DELETE]", delErr.message);
      return res.status(500).json({ error: "Erreur lors de la suppression." });
    }

    console.log("[DELETE] Request", id, "deleted");
    return res.status(200).json({ message: "Demande supprimée avec succès." });
  } catch (err) {
    console.error("[DELETE /api/requests/:id]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── POST /api/requests/:id/signal ─ Flag Request ─────
app.post("/api/requests/:id/signal", requireAuth, requireClient, async (req, res) => {
  try {
    const { id } = req.params;
    const now = new Date().toISOString();

    const { data: existing, error: fetchErr } = await supabase
      .from("requests")
      .select("client_id")
      .eq("id", id)
      .single();

    if (fetchErr || !existing) {
      console.error("[SIGNAL] Not found:", id);
      return res.status(404).json({ error: "Demande introuvable." });
    }

    if (existing.client_id !== req.user.id) {
      console.error("[SIGNAL] Unauthorized user", req.user.id, "for request", id);
      return res.status(403).json({ error: "Accès refusé." });
    }

    const { error: sigErr } = await supabase
      .from("requests")
      .update({ is_flagged: true, flagged_at: now, updated_at: now })
      .eq("id", id);

    if (sigErr) {
      console.error("[SIGNAL]", sigErr.message);
      return res.status(500).json({ error: "Erreur lors du signalement." });
    }

    console.log(`[SIGNAL RECEIVED] Request ${id} flagged by client`);
    return res.status(200).json({ message: "Retard signalé avec succès aux administrateurs" });
  } catch (err) {
    console.error("[POST /api/requests/:id/signal]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── GET /api/profile ─ Sync Profile ──────────────────
app.get("/api/profile", requireAuth, requireClient, async (req, res) => {
  try {
    let { data: profile, error } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", req.user.id)
      .single();

    if (error && error.code === "PGRST116") {
      const { data: created, error: createErr } = await supabase
        .from("profiles")
        .insert({
          id: req.user.id,
          email: req.user.email,
          full_name: req.user.user_metadata?.full_name || req.user.user_metadata?.name || null,
          avatar_url: req.user.user_metadata?.avatar_url || null,
          role: "client",
        })
        .select()
        .single();

      if (createErr) {
        console.error("[DB CREATE PROFILE]", createErr.message);
        return res.status(500).json({ error: "Erreur lors de la création du profil." });
      }

      profile = created;
    } else if (error) {
      console.error("[DB SELECT PROFILE]", error.message);
      return res.status(500).json({ error: "Erreur lors de la récupération du profil." });
    }

    return res.json(profile);
  } catch (err) {
    console.error("[GET /api/profile]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ═══════════════════════════════════════════════════════
//  ADMIN ENDPOINTS
// ═══════════════════════════════════════════════════════

// ─── GET /api/admin/requests ─ All Requests ───────────
app.get("/api/admin/requests", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { data: requests, error } = await supabase
      .from("requests")
      .select("*")
      .order("created_at", { ascending: false });

    if (error) {
      console.error("[ADMIN GET REQUESTS]", error.message);
      return res.status(500).json({ error: "Erreur lors de la récupération des demandes." });
    }

    const clientIds = [...new Set((requests || []).map((r) => r.client_id).filter(Boolean))];

    let profileMap = {};
    if (clientIds.length > 0) {
      const { data: profiles } = await supabase
        .from("profiles")
        .select("id, email, full_name, avatar_url")
        .in("id", clientIds);

      if (profiles) {
        for (const p of profiles) {
          profileMap[p.id] = { id: p.id, email: p.email, full_name: p.full_name, avatar_url: p.avatar_url };
        }
      }
    }

    const enriched = (requests || []).map((r) => ({
      ...r,
      client: profileMap[r.client_id] || null,
    }));

    console.log("[ADMIN GET REQUESTS] Raw data:", JSON.stringify(enriched));

    const sorted = enriched.sort((a, b) => {
      const aIsCritical = a.urgency_level === "critical" ? 0 : 1;
      const bIsCritical = b.urgency_level === "critical" ? 0 : 1;
      if (aIsCritical !== bIsCritical) return aIsCritical - bIsCritical;
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });

    console.log(`[ADMIN GET REQUESTS] Fetched ${sorted.length} requests`);
    return res.status(200).json(sorted);
  } catch (err) {
    console.error("[GET /api/admin/requests]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── GET /api/admin/requests/:id ─ Single Request ─────
app.get("/api/admin/requests/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const { data: request, error } = await supabase
      .from("requests")
      .select("*")
      .eq("id", id)
      .single();

    if (error || !request) {
      console.error("[ADMIN GET REQUEST] Not found:", id);
      return res.status(404).json({ error: "Demande introuvable." });
    }

    let client = null;
    if (request.client_id) {
      const { data: profile } = await supabase
        .from("profiles")
        .select("id, email, full_name, avatar_url")
        .eq("id", request.client_id)
        .single();

      if (profile) {
        client = { id: profile.id, email: profile.email, full_name: profile.full_name, avatar_url: profile.avatar_url };
      }
    }

    return res.status(200).json({ ...request, client });
  } catch (err) {
    console.error("[GET /api/admin/requests/:id]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── PATCH /api/admin/requests/:id ─ Admin Update ─────
app.patch("/api/admin/requests/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, current_step, admin_notes, arrival_date, end_date, duration_days, price_eur, payment_status, cancellation_reason, amount_paid, balance_due } = req.body;
    const now = new Date().toISOString();

    const allowedStatuses = ["pending", "reviewing", "scheduled", "completed", "cancelled"];

    if (status && !allowedStatuses.includes(status)) {
      console.error("[ADMIN PATCH] Invalid status:", status);
      return res.status(400).json({
        error: `Statut invalide. Valeurs acceptées: ${allowedStatuses.join(", ")}`,
      });
    }

    let step = null;
    if (current_step !== undefined && current_step !== null) {
      step = Number(current_step);
      if (!Number.isInteger(step) || step < 1 || step > 4) {
        return res.status(400).json({ error: "current_step doit être un entier entre 1 et 4." });
      }
    }

    const allowedPayments = ["Non payé", "Avance", "Payé"];
    if (payment_status && !allowedPayments.includes(payment_status)) {
      return res.status(400).json({
        error: `payment_status invalide. Valeurs acceptées: ${allowedPayments.join(", ")}`,
      });
    }

    const updatePayload = { updated_at: now };
    if (status) updatePayload.status = status;
    if (step !== null) updatePayload.current_step = step;
    if (admin_notes !== undefined && admin_notes !== null) {
      updatePayload.admin_notes = typeof admin_notes === "string" ? admin_notes.trim() : admin_notes;
    }
    if (arrival_date) updatePayload.arrival_date = arrival_date;
    if (end_date) updatePayload.end_date = end_date;
    if (duration_days !== undefined && duration_days !== null) {
      updatePayload.duration_days = Number(duration_days);
    }
    if (price_eur !== undefined && price_eur !== null) {
      updatePayload.price_eur = Number(price_eur);
    }
    if (payment_status) updatePayload.payment_status = payment_status;
    if (cancellation_reason !== undefined && cancellation_reason !== null) {
      updatePayload.cancellation_reason = cancellation_reason;
    }
    if (amount_paid !== undefined && amount_paid !== null) {
      updatePayload.amount_paid = Number(amount_paid);
    }
    if (balance_due !== undefined && balance_due !== null) {
      updatePayload.balance_due = Number(balance_due);
    }

    const { data, error } = await supabase
      .from("requests")
      .update(updatePayload)
      .eq("id", id)
      .select()
      .single();

    if (error || !data) {
      console.error("[ADMIN PATCH]", error?.message);
      return res.status(404).json({ error: "Demande introuvable." });
    }

    io.to(data.client_id).emit("request_updated", data);
    io.to("admin").emit("request_updated", data);
    console.log(`[SOCKET] Emitted request_updated for ${id} to client ${data.client_id} and admin room`);

    console.log(`[ADMIN PATCH] Request ${id} updated:`, updatePayload);
    return res.status(200).json(data);
  } catch (err) {
    console.error("[PATCH /api/admin/requests/:id]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── GET /api/admin/metrics ─ Dashboard Stats ─────────
app.get("/api/admin/metrics", requireAuth, requireAdmin, async (req, res) => {
  try {
    const [
      { count: total, error: err1 },
      { count: pending, error: err2 },
      { count: critical, error: err3 },
      { count: flagged, error: err4 },
    ] = await Promise.all([
      supabase.from("requests").select("*", { count: "exact", head: true }),
      supabase
        .from("requests")
        .select("*", { count: "exact", head: true })
        .eq("status", "pending"),
      supabase
        .from("requests")
        .select("*", { count: "exact", head: true })
        .eq("urgency_level", "critical"),
      supabase
        .from("requests")
        .select("*", { count: "exact", head: true })
        .eq("is_flagged", true),
    ]);

    if (err1 || err2 || err3 || err4) {
      console.error("[ADMIN METRICS]", { err1, err2, err3, err4 });
      return res.status(500).json({ error: "Erreur lors du calcul des métriques." });
    }

    const metrics = {
      total_active: total,
      pending_count: pending,
      critical_count: critical,
      flagged_count: flagged,
    };

    console.log("[ADMIN METRICS]", metrics);
    return res.status(200).json(metrics);
  } catch (err) {
    console.error("[GET /api/admin/metrics]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── GET /api/admin/stats ─ Frontend Stats Alias ──────
app.get("/api/admin/stats", requireAuth, requireAdmin, async (req, res) => {
  console.log("[Admin API] Stats endpoint successfully hit");
  try {
    const [
      { count: total, error: err1 },
      { count: pending, error: err2 },
      { count: critical, error: err3 },
      { count: flagged, error: err4 },
    ] = await Promise.all([
      supabase.from("requests").select("*", { count: "exact", head: true }),
      supabase
        .from("requests")
        .select("*", { count: "exact", head: true })
        .eq("status", "pending"),
      supabase
        .from("requests")
        .select("*", { count: "exact", head: true })
        .eq("urgency_level", "critical"),
      supabase
        .from("requests")
        .select("*", { count: "exact", head: true })
        .eq("is_flagged", true),
    ]);

    if (err1 || err2 || err3 || err4) {
      console.error("[ADMIN STATS]", { err1, err2, err3, err4 });
      return res.status(500).json({ error: "Erreur lors du calcul des statistiques." });
    }

    const stats = {
      totalRequests: total,
      pending: pending,
      critical: critical,
      flagged: flagged,
    };

    console.log("[ADMIN STATS]", stats);
    return res.status(200).json(stats);
  } catch (err) {
    console.error("[GET /api/admin/stats]", err.message);
    return res.status(500).json({ error: "Une erreur inattendue est survenue." });
  }
});

// ─── Global Error Handler ──────────────────────────────
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(413).json({ error: "Fichier dépasse la limite de 10 Mo." });
    }
    return res.status(400).json({ error: `Erreur d'upload: ${err.message}` });
  }
  console.error("[UNHANDLED]", err.message);
  return res.status(500).json({ error: "Erreur interne du serveur." });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[Alliance LuxCare] Server running on port ${PORT} (${NODE_ENV})`);
});
