import express from "express";
import cors from "cors";
import { Pool } from "pg";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import crypto from "crypto";
// 💡 جديد: استيراد Buffer لمعالجة Basic Auth
import { Buffer } from 'buffer';

// 🆕 جديد: استيراد مكتبة moment-timezone للتحقق من التوقيت الدقيق في قطر
import moment from "moment-timezone";

const app = express();
const port = 3000;

// 🆕 ثوابت التوقيت والتحقق
const QATAR_TIMEZONE = 'Asia/Qatar'; // المنطقة الزمنية المعتمدة
const REGISTRATION_CUTOFF_MINUTES = 15; // إغلاق التسجيل قبل 15 دقيقة من بداية الامتحان

// =======================
// 📂 إعداد المسارات الأساسية
// =======================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// يخدم هذا السطر الملفات الثابتة، بما في ذلك index.html عند المسار /
app.use(express.static(path.join(__dirname, "public")));
app.use(cors());
app.use(express.json());

// =======================
// 🧠 إعداد قاعدة البيانات (Neon)
// =======================
const connectionString = process.env.DATABASE_URL || "postgresql://neondb_owner:npg_0vOKkfucTr8x@ep-flat-fog-ad6y37qj-pooler.c-2.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require";

if (!connectionString) {
  console.error("❌ FATAL: DATABASE_URL environment variable is not set. Exiting.");
}

const pool = new Pool({
  connectionString: connectionString,
  ssl: { rejectUnauthorized: false }, 
  keepAlive: true, 
  idleTimeoutMillis: 30000,
});

// اختبار الاتصال عند بدء التشغيل
pool.query("SELECT 1")
  .then(() => console.log("✅ Connected to Neon Postgres"))
  .catch(err => {
    console.error("❌ DB initial connection error:", err);
  });

// معالج الأخطاء لمنع انهيار السيرفر إذا انقطع اتصال خامل
pool.on("error", (err) => {
  console.error("⚠️ Unexpected error on idle client (DB connection probably dropped)", err); 
});

// =======================
// ☁️ إعداد Cloudflare R2
// =======================
const R2_ACCOUNT_ID = process.env.R2_ACCOUNT_ID || "bff89b968c6e33460fa8c87486571cc4";
const R2_ACCESS_KEY_ID = process.env.R2_ACCESS_KEY_ID || "c6a13d504f60107741d64725bfdf3820";
const R2_SECRET_ACCESS_KEY = process.env.R2_SECRET_ACCESS_KEY || "3a092a287cd68828d3d7c8dc5a5b29d7e3c84d197b3cc97b3335c31e3cce71f4";
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME || "exam-bucket";
// نقطة نهاية Cloudflare R2
const R2_PUBLIC_URL_PREFIX = `https://pub-f338e3c444bb4dbda80f9b71540da639.r2.dev`;


const s3Client = new S3Client({
  region: "auto",
  endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: R2_ACCESS_KEY_ID,
    secretAccessKey: R2_SECRET_ACCESS_KEY,
  },
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

// =======================
// ⚙️ توليد توكن فريد
// =======================
function generateUniqueToken(length = 12) {
  return crypto.randomBytes(length).toString("hex");
}

// =======================
// 🛡️ دالة Basic Auth Middleware
// =======================
const basicAuth = (req, res, next) => {
  const ADMIN_USER = 'lucy';
  const ADMIN_PASS = 'lucy-20';
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Access denied. Authentication required.');
  }

  try {
    const [scheme, credentials] = authHeader.split(' ');

    if (scheme !== 'Basic' || !credentials) {
      res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
      return res.status(401).send('Invalid authentication format.');
    }

    // فك تشفير البيانات (username:password)
    const decoded = Buffer.from(credentials, 'base64').toString();
    const [username, password] = decoded.split(':');

    if (username === ADMIN_USER && password === ADMIN_PASS) {
      next(); // نجاح التوثيق
    } else {
      res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
      return res.status(401).send('Invalid credentials.');
    }
  } catch (e) {
    console.error("Auth error:", e);
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin Area"');
    return res.status(401).send('Authentication processing error.');
  }
};


// =======================
// 🔗 API Endpoints (مسارات صفحات الإدارة الآن محمية)
// =======================

// 🔒 مسارات الإدارة المحمية بـ Basic Auth
app.get("/exams/:id/questions-admin", basicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "exams", "questions-admin.html"));
});
app.get("/exams/add", basicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "exams", "add.html"));
});

app.get("/exams/add-section", basicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "exams", "add-section.html"));
});

app.get("/exams/add-questions", basicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "exams", "add-question.html"));
});

app.get("/exams/admin/results", basicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "exams", "admin-results.html"));
});

// 🔓 مسارات المستخدم العادي (الغير محمية)

// صفحة الأسئلة
app.get("/exam/:id/questions", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "exams", "questions.html"));
});

// صفحة بدء الامتحان 
app.get("/exams/applicant-exam", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "exams", "applicant-exam.html"));
});

// صفحة التسجيل 
app.get("/exams/applicant-register", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "exams", "applicant-register.html"));
});

// التحقق من رمز الدخول وتحديد الامتحان
app.post("/api/validate_exam_token", async (req, res) => {
 const { token } = req.body;

 if (!token) {
  return res.status(400).json({ success: false, error: "رمز الدخول مطلوب" });
 }

try {
  // 1. جلب معلومات الطالب (تم إضافة finished)
  const applicantResult = await pool.query(
   "SELECT id, specialization, finished, invited FROM applicants WHERE id=$1",
   [token] // ✅ هذا هو السطر الذي أُضيف أو نُقل خارج التعليق
  );
  if (applicantResult.rows.length === 0) {
   return res.json({ success: false, error: "رمز دخول غير صحيح أو غير مسجل." });
  }

  const applicant = applicantResult.rows[0];

  if (applicant.invited === false) {
        return res.json({ 
            success: false, 
            // رسالة خطأ جديدة خاصة بعدم الدعوة
            error: "غير مدعو للامتحان." 
        });
    }

    // ⭐️ 2. التحقق من حالة الإنهاء (قبل التحقق من التوقيت)
    if (applicant.finished === true) {
        return res.json({ 
            success: false, 
            // رسالة الخطأ هذه سيتم استخدامها في applicant-exam.html لإجراء التوجيه
            error: "لقد أكملت الامتحان مسبقًا." 
        });
    }

  // جلب الامتحان المطابق للتخصص
  const examResult = await pool.query(
   "SELECT id, title, start_time_qat, end_time_qat FROM exams WHERE title=$1 ORDER BY id DESC LIMIT 1",
   [applicant.specialization]
  );

  if (examResult.rows.length === 0) {
   return res.json({ success: false, error: "لم يتم العثور على امتحان لهذا التخصص" });
  }

  const exam = examResult.rows[0];

  // التحقق من التوقيت على السيرفر
  const now = new Date();
  const start = new Date(exam.start_time_qat);
  const end = new Date(exam.end_time_qat);

  const optionsDate = { timeZone: "Asia/Qatar", day: '2-digit', month: '2-digit', year: 'numeric' };
  const optionsTime = { timeZone: "Asia/Qatar", hour: '2-digit', minute: '2-digit' };

  // تمرير الأوقات المنسقة بشكل موثوق
  exam.startDateStr = start.toLocaleDateString("en-GB", optionsDate);
  exam.startTimeStr = start.toLocaleTimeString("en-GB", optionsTime);
  exam.endDateStr = end.toLocaleDateString("en-GB", optionsDate);
  exam.endTimeStr = end.toLocaleTimeString("en-GB", optionsTime);

  // إذا كان الوقت خارج الإطار الزمني المسموح (يتم التحقق منه فقط إذا لم يكن قد أنهى مسبقاً)
  if (now < start || now > end) {
   return res.json({
    success: false,
    error: "الامتحان غير متاح حالياً.",
    exam
   });
  }

  // كل شيء صحيح (غير مكمل، والتوقيت مسموح)
  res.json({
   success: true,
   examId: exam.id,
   exam,
   // ✨ الحقول الضرورية لتخزينها في الواجهة الأمامية ✨
   validationToken: token, // سيتم تخزينه في sessionStorage
   applicantId: applicant.id, // سيتم تخزينه في localStorage
   examEndTime: end.toISOString() // سيتم تخزينه في sessionStorage
  });

 } catch (err) {
  console.error("POST /api/validate_exam_token error:", err);
  res.status(500).json({ success: false, error: "Database or server error" });
 }
});
// 🆕 جلب إجابة طالب لسؤال محدد (تستخدمها دوال استمرارية الحالة في الفرونت إند)
// 🆕 جلب إجابة طالب لسؤال محدد
app.get("/api/answers", async (req, res) => {
  const { exam_id, applicant_id, question_id } = req.query;

  if (!exam_id || !applicant_id || !question_id) {
    return res.status(400).json({ error: "exam_id, applicant_id, و question_id مطلوبون" });
  }

  try {
    const result = await pool.query(
      // 💡 التعديل هنا: إضافة LEFT JOIN لربط جدول الخيارات (options)
      `SELECT 
        a.answer_text, 
        a.audio_url, 
        a.answer_option_id, 
        a.submitted_at,
        o.text AS option_text -- 🆕 جلب نص الخيار المختار
      FROM answers a
      LEFT JOIN options o ON a.answer_option_id = o.id
      WHERE a.exam_id = $1 AND a.applicant_id = $2 AND a.question_id = $3`,
      [exam_id, applicant_id, question_id]
    );
    // يُفترض أن الإجابة واحدة (بسبب UNIQUE constraint في DB)
    res.json(result.rows); 
  } catch (err) {
    console.error("GET /api/answers error:", err);
    res.status(500).json({ error: "Database error" });
  }
});
// تسجيل متقدم وتوليد توكن
app.post("/api/applicant/register_token", async (req, res) => {
  const { name, email, specialization } = req.body; 

  if (!name || !email || !specialization) {
    return res.status(400).json({ error: "الاسم، البريد الإلكتروني والتخصص مطلوبان للتسجيل." });
  }

  try {
        // 1. جلب بيانات الامتحان المتعلقة بالتخصص (مطلوبة للتحقق من التوقيت ولعرض التفاصيل)
    const examResult = await pool.query(
      "SELECT id, title, start_time_qat, end_time_qat FROM exams WHERE title=$1 ORDER BY id DESC LIMIT 1",
      [specialization]
    );

        if (examResult.rows.length === 0) {
             return res.status(500).json({ success: false, error: "لم يتم العثور على امتحان لهذا التخصص." });
        }
        
        const examData = examResult.rows[0];
        
        // 2. التحقق من وجود البريد الإلكتروني (هل هو مسجل مسبقًا؟)
    const checkResult = await pool.query(
      "SELECT id FROM applicants WHERE LOWER(email) = LOWER($1)",
      [email]
    );

        // 3. 🆕 منطق التحقق من موعد إغلاق التسجيل (يتم تنفيذه فقط للبريد الإلكتروني الجديد)
        // إذا كان البريد غير مسجل مسبقاً، نطبق قيد الـ 15 دقيقة
        if (checkResult.rows.length === 0) {
            
            const examStartMoment = moment.tz(examData.start_time_qat, QATAR_TIMEZONE);
            // حساب الموعد النهائي للتسجيل: بداية الامتحان - 15 دقيقة
            const deadlineMoment = examStartMoment.clone().subtract(REGISTRATION_CUTOFF_MINUTES, 'minutes');
            // الوقت الحالي في منطقة قطر الزمنية
            const nowMoment = moment.tz(QATAR_TIMEZONE);

            if (nowMoment.isSameOrAfter(deadlineMoment)) {
                 // ❌ رفض التسجيل وإرسال رسالة الخطأ للواجهة الأمامية
                return res.status(403).json({ 
                    success: false, 
                    error: `لقد تم إغلاق باب التسجيل. لا يمكن التسجيل قبل ${REGISTRATION_CUTOFF_MINUTES} دقيقة من موعد الامتحان.` 
                });
            }
        }

        // 4. إذا كان البريد الإلكتروني مسجل مسبقًا، نعرض الرمز الحالي
    if (checkResult.rows.length > 0) {
      const start = new Date(examData.start_time_qat);
      const optionsDate = { timeZone: "Asia/Qatar", day: '2-digit', month: '2-digit', year: 'numeric' };
      const optionsTime = { timeZone: "Asia/Qatar", hour: '2-digit', minute: '2-digit' };

      let exam = {};
      exam.displayDate = start.toLocaleDateString("en-GB", optionsDate);
      exam.displayTime = start.toLocaleTimeString("en-GB", optionsTime);

      return res.json({
        success: true,
        message: "هذا البريد الإلكتروني مسجل مسبقًا. تم عرض الرمز الحالي.",
        token: checkResult.rows[0].id,
        exam
      });
    }

        // 5. إذا كان البريد الإلكتروني جديداً ومر بالتحقق الزمني، ننشئ توكن جديد ونحفظه
    const token = generateUniqueToken(12);

    const insertResult = await pool.query(
      "INSERT INTO applicants (id, email, specialization, name) VALUES ($1, $2, $3, $4) RETURNING id",
      [token, email, specialization, name]
    );

    const start = new Date(examData.start_time_qat);
    const optionsDate = { timeZone: "Asia/Qatar", day: '2-digit', month: '2-digit', year: 'numeric' };
    const optionsTime = { timeZone: "Asia/Qatar", hour: '2-digit', minute: '2-digit' };

    let exam = {};
    exam.displayDate = start.toLocaleDateString("en-GB", optionsDate);
    exam.displayTime = start.toLocaleTimeString("en-GB", optionsTime);


    res.json({
      success: true,
      message: "تم التسجيل بنجاح. هذا هو رمز الدخول الخاص بك.",
      token: insertResult.rows[0].id,
      exam
    });
  } catch (err) {
    console.error("POST /api/applicant/register_token error:", err);
    res.status(500).json({ success: false, error: "خطأ في قاعدة البيانات أثناء التسجيل." });
  }
});

// إضافة امتحان
app.post("/api/exams", async (req, res) => {
  try {
    const { title, description, start_time_qat, end_time_qat } = req.body;
    if (!title || !start_time_qat || !end_time_qat)
      return res.status(400).json({ error: "جميع الحقول المطلوبة مطلوبة" });

    const result = await pool.query(
      "INSERT INTO exams (title, description, start_time_qat, end_time_qat) VALUES ($1,$2,$3,$4) RETURNING *",
      [title, description, start_time_qat, end_time_qat]
    );

    res.json({ success: true, exam: result.rows[0] });
  } catch (err) {
    console.error("POST /api/exams error:", err);
    res.status(500).json({ success: false, error: "Database error" });
  }
});

// جلب جميع الامتحانات
app.get("/api/exams", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, title, description, start_time_qat, end_time_qat, created_at FROM exams ORDER BY id DESC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("GET /api/exams error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// جلب تفاصيل امتحان
app.get("/api/exams/:examId", async (req, res) => {
  const { examId } = req.params;
  try {
    const result = await pool.query(
      "SELECT id, title, description, start_time_qat, end_time_qat, created_at FROM exams WHERE id=$1",
      [examId]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "الامتحان غير موجود" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("GET /api/exams/:examId error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// جلب تفاصيل امتحان بواسطة العنوان (Title)
app.get("/api/exams/by_title/:examTitle", async (req, res) => {
  const { examTitle } = req.params;
  try {
    const result = await pool.query(
      "SELECT id, title, description, start_time_qat, end_time_qat, created_at FROM exams WHERE title=$1 ORDER BY id DESC LIMIT 1",
      [examTitle]
    );

    if (result.rows.length === 0) return res.status(404).json({ error: "الامتحان غير موجود" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("GET /api/exams/by_title/:examTitle error:", err);
    res.status(500).json({ error: "Database error" });
  }
});
// إضافة قسم
app.post("/api/sections", async (req, res) => {
  try {
    const { exam_id, title, order } = req.body;
    if (!exam_id || !title) return res.status(400).json({ error: "exam_id و title مطلوبان" });

    const result = await pool.query(
      'INSERT INTO exam_sections (exam_id, title, "order") VALUES ($1,$2,$3) RETURNING *',
      [exam_id, title, order || 1]
    );

    res.json({ success: true, section: result.rows[0] });
  } catch (err) {
    console.error("POST /api/sections error:", err);
    res.status(500).json({ success: false, error: "Database error" });
  }
});



// جلب أقسام الامتحان
app.get("/api/sections", async (req, res) => {
  const { exam_id } = req.query;
  if (!exam_id) return res.status(400).json({ error: "exam_id مطلوب" });

  try {
    const result = await pool.query(
      'SELECT id, title, "order" FROM exam_sections WHERE exam_id=$1 ORDER BY "order"',
      [exam_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("GET /api/sections error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// إضافة سؤال
app.post("/api/questions", async (req, res) => {
  try {
    const { section_id, text, type, order, options } = req.body;
    if (!section_id || !text || !type) return res.status(400).json({ error: "الرجاء إدخال جميع الحقول المطلوبة" });

    const qResult = await pool.query(
      'INSERT INTO questions (section_id, text, type, "order") VALUES ($1,$2,$3,$4) RETURNING *',
      [section_id, text, type, order || 1]
    );
    const question = qResult.rows[0];

    if (type === "multiple_choice" && options && options.length > 0) {
      const optionValues = options.map(opt => [question.id, opt.text, opt.is_correct || false]).flat();
      const placeholders = options.map((_, i) => `($${i * 3 + 1}, $${i * 3 + 2}, $${i * 3 + 3})`).join(',');

      await pool.query(
        `INSERT INTO options (question_id, text, is_correct) VALUES ${placeholders}`,
        optionValues
      );
    }

    res.json({ success: true, question });
  } catch (err) {
    console.error("POST /api/questions error:", err);
    res.status(500).json({ success: false, error: "Database error" });
  }
});

// جلب أسئلة الامتحان
// 🌟 التعديل المطلوب رقم 2: جلب الإجابة السابقة للطالب (applicant_id)
app.get("/api/exams/:examId/questions", async (req, res) => {
  const { examId } = req.params;
  // يجب إرسال applicant_id كـ Query parameter
  const { applicant_id } = req.query; 

  if (!applicant_id) {
    return res.status(400).json({ error: "applicant_id مطلوب لجلب حالة إجابة المتقدم." });
  }

  try {
    const result = await pool.query(
      `SELECT 
      q.id, q.text, q.type, q.order, s.title AS section_title, s.id AS section_id,
      a.answer_text, a.audio_url, a.answer_option_id
      FROM questions q
      JOIN exam_sections s ON q.section_id = s.id
      LEFT JOIN answers a ON q.id = a.question_id AND a.applicant_id = $2 AND a.exam_id = $1
      WHERE s.exam_id=$1
      ORDER BY s.order, q.order`,
      [examId, applicant_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("GET /api/exams/:examId/questions error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// جلب خيارات السؤال
app.get("/api/questions/options", async (req, res) => {
  const { question_id } = req.query;
  if (!question_id) return res.status(400).json({ error: "question_id مطلوب" });

  try {
    const result = await pool.query(
      "SELECT id, text FROM options WHERE question_id=$1",
      [question_id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("GET /api/questions/options error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// حفظ إجابة الطالب
app.post("/api/answers", async (req, res) => {
  const { exam_id, question_id, applicant_id, answer_text, answer_option_id, audio_url } = req.body;
  if (!exam_id || !question_id || !applicant_id) {
    return res.status(400).json({ error: "الرجاء إدخال الحقول الأساسية: رقم الامتحان والسؤال والتوكن." });
  }

  try {
    const questionTypeResult = await pool.query(
      "SELECT type FROM questions q JOIN exam_sections s ON q.section_id = s.id WHERE q.id = $1 AND s.exam_id = $2",
      [question_id, exam_id]
    );

    if (questionTypeResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: "السؤال أو الامتحان غير موجود." });
    }

    const questionType = questionTypeResult.rows[0].type;
    let answerTextFinal = null;
    let answerOptionIdFinal = null;
    let audioUrlFinal = null;

    // المنطق الجديد: السماح بحفظ أي حقل مُرسل كجزء من الإجابة الشاملة
    answerTextFinal = answer_text || null;
    answerOptionIdFinal = answer_option_id || null;
    audioUrlFinal = audio_url || null;

    // يجب فحص الحقول غير الفارغة
    if (!answerTextFinal && !answerOptionIdFinal && !audioUrlFinal) {
      return res.status(400).json({ success: false, error: "يجب توفير إجابة نصية أو اختيار أو رابط صوتي." });
    }

    // يجب التأكد من تمرير البيانات المفلترة لتجنب حفظ إجابات متعددة في نفس الوقت
    await pool.query(
      `INSERT INTO answers (exam_id, question_id, applicant_id, answer_text, answer_option_id, audio_url)
      VALUES ($1,$2,$3,$4,$5,$6)
      ON CONFLICT (applicant_id, question_id) DO UPDATE SET
        answer_text = $4, -- يتم التحديث بشكل كامل، لضمان مسح النص إذا تم إرسال نص فارغ (مثل الحالة النصية)
        answer_option_id = $5, 
        audio_url = $6,
        submitted_at = NOW()`,
      [exam_id, question_id, applicant_id, answerTextFinal, answerOptionIdFinal, audioUrlFinal]
    );
    res.json({ success: true, message: "تم حفظ الإجابة بنجاح." });
  } catch (err) {
    console.error("POST /api/answers error:", err);
    res.status(500).json({ success: false, error: "Database error" });
  }
});
// ----------------------------------------------------
// 🆕 جلب جميع المتقدمين لتخصص معين (للاستخدام الإداري)
app.get("/api/applicants/by_specialization/:specialization", async (req, res) => {
  const { specialization } = req.params;
  try {
    const result = await pool.query(
      "SELECT id, name, email FROM applicants WHERE specialization=$1 ORDER BY name ASC",
      [specialization]
    );
    res.json(result.rows);
  } catch (err) {
    console.error("GET /api/applicants/by_specialization error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// 🌟 نقطة نهاية رفع ملف الصوت
app.post("/api/upload/audio", upload.single("audio"), async (req, res) => {
  const { applicant_id, question_id } = req.body;

  if (!req.file) return res.status(400).json({ error: "لم يتم رفع أي ملف صوتي" });

  try {
    // توليد اسم ملف فريد وموثوق
    const fileExtension = path.extname(req.file.originalname) || '.mp3';
    // استخدم applicant_id و question_id لضمان مرجعية الملف
    const uniqueFileName = `${applicant_id}-${question_id}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}${fileExtension}`;

    const uploadParams = {
      Bucket: R2_BUCKET_NAME,
      Key: `audio/${uniqueFileName}`,
      Body: req.file.buffer,
      ContentType: req.file.mimetype,
    };

    await s3Client.send(new PutObjectCommand(uploadParams));

    // **هنا نقوم فقط بإرجاع الرابط**
    const publicUrl = `${R2_PUBLIC_URL_PREFIX}/audio/${uniqueFileName}`;

    res.json({ success: true, audioUrl: publicUrl }); // تغيير اسم المفتاح إلى audioUrl ليطابق الواجهة الأمامية

  } catch (err) {
    console.error("R2 Upload Error:", err);
    res.status(500).json({ success: false, error: "فشل رفع الملف إلى R2" });
  }
});

app.get("/exams/not-invited", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "exams", "not-invited.html"));
});

// 1. مسار لعرض صفحة "تم إنهاء الامتحان"
app.get('/exams/finished', (req, res) => {
    // افترض أن ملف finished.html موجود في مجلد public
  res.sendFile(path.join(__dirname, "public", "exams", "finished.html"));
});

// في ملف server.js - إضافة مسار لتحديث حالة الانتهاء
app.patch("/api/applicant/:id/finish", async (req, res) => {
    const { id } = req.params; // هو applicantId
    const { finished } = req.body;

    // تحقق من وجود الـ ID والقيمة الصحيحة
    if (!id || finished !== true) {
        return res.status(400).json({ success: false, error: "بيانات الإدخال غير صالحة." });
    }

    try {
        const result = await pool.query(
            "UPDATE applicants SET finished = TRUE WHERE id = $1 AND finished = FALSE RETURNING id",
            [id]
        );

        if (result.rows.length === 0) {
            // يحدث هذا إذا لم يتم العثور على المتقدم، أو إذا كانت finished بالفعل TRUE
            return res.status(404).json({ success: false, error: "المتقدم غير موجود أو تم الانتهاء مسبقاً." });
        }

        // إرسال رد النجاح
        res.json({ success: true, message: "تم تسجيل حالة الانتهاء بنجاح." });

    } catch (err) {
        console.error("PATCH /api/applicant/:id/finish error:", err);
        res.status(500).json({ success: false, error: "خطأ في قاعدة البيانات أو الخادم." });
    }
});
app.use((req, res, next) => {
    // إرسال كود الحالة 404
    res.status(404);

    // التحقق من نوع الطلب
    if (req.accepts('html')) {
        // إذا كان الطلب لصفحة HTML، أرسل ملف تصميم 404.html
        res.sendFile(path.join(__dirname, 'public', '404.html'));
        return;
    }

    // إذا كان الطلب لـ API أو أي شيء آخر، أرسل JSON
    if (req.accepts('json')) {
        res.json({ error: 'Not Found', message: 'The requested resource was not found on this server.' });
        return;
    }

    // للمطالبات الأخرى، أرسل نصًا عاديًا
    res.send('404 Not Found');
});

// =======================
// 🚀 تشغيل السيرفر
// =======================
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});