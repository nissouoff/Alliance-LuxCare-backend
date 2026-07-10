import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import multer from "multer";
import { createClient } from "@supabase/supabase-js";

// ─── Environment Variables ────────────────────────────
const {
  PORT = 5000,
  NODE_ENV = "development",
  FRONTEND_URL = "http://localhost:3000",
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
} = process.env;

for (const key of ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]) {
  if (!process.env[key]) {
    console.error(`[FATAL] Missing env: ${key}`);
    process.exit(1);
  }
}

// ─── Supabase Admin Client ────────────────────────────
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
});

// ─── Express App ──────────────────────────────────────
const app = express();

app.use(helmet());
app.use(
  cors({
    origin: FRONTEND_URL,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  }),
);
app.use(express.json({ limit: "1mb" }));

// ─── Multer (in-memory, 10 MB per file, max 5 files) ─
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

// ─── Storage Upload Helper ────────────────────────────
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

// ═══════════════════════════════════════════════════════
//  ENDPOINTS
// ═══════════════════════════════════════════════════════

// ─── Health Check ──────────────────────────────────────
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", env: NODE_ENV, timestamp: new Date().toISOString() });
});

// ─── POST /api/requests ─ Create Coordination Request ─
app.post("/api/requests", requireAuth, upload.array("documents", 5), async (req, res) => {
  try {
    console.log("[Backend Received Body]:", req.body);
    console.log("[Backend Received Files]:", req.files);

    const {
      fullName,
      phone,
      residenceCountry,
      pathwayCountry,
      natureOfRequest,
      contactType,
      urgencyLevel,
      message,
    } = req.body;

    if (!fullName) console.log("Validation failed: fullName is missing");
    if (!phone) console.log("Validation failed: phone is missing");
    if (!residenceCountry) console.log("Validation failed: residenceCountry is missing");
    if (!pathwayCountry) console.log("Validation failed: pathwayCountry is missing");
    if (!natureOfRequest) console.log("Validation failed: natureOfRequest is missing");
    if (!contactType) console.log("Validation failed: contactType is missing");
    if (!urgencyLevel) console.log("Validation failed: urgencyLevel is missing");
    if (!message) console.log("Validation failed: message is missing");

    const missingFields = [];
    if (!fullName) missingFields.push("fullName");
    if (!phone) missingFields.push("phone");
    if (!residenceCountry) missingFields.push("residenceCountry");
    if (!pathwayCountry) missingFields.push("pathwayCountry");
    if (!natureOfRequest) missingFields.push("natureOfRequest");
    if (!contactType) missingFields.push("contactType");
    if (!urgencyLevel) missingFields.push("urgencyLevel");
    if (!message) missingFields.push("message");

    if (missingFields.length > 0) {
      console.error("[POST /api/requests] 400 Bad Request — Missing fields:", missingFields.join(", "));
      return res.status(400).json({ error: `Champs manquants: ${missingFields.join(", ")}` });
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
      full_name: fullName,
      phone,
      residence_country: residenceCountry,
      pathway_country: pathwayCountry,
      nature_of_request: natureOfRequest,
      contact_type: contactType,
      urgency_level: urgencyLevel,
      message,
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

// ─── GET /api/requests ─ Fetch Client's Requests ──────
app.get("/api/requests", requireAuth, async (req, res) => {
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

// ─── GET /api/profile ─ Sync Profile ──────────────────
app.get("/api/profile", requireAuth, async (req, res) => {
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

// ─── Start ────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`[Alliance LuxCare] Server running on port ${PORT} (${NODE_ENV})`);
});
