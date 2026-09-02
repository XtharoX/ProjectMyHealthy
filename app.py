import json, sqlite3, secrets, os, urllib.request, urllib.error, hmac, hashlib, base64
from pathlib import Path
from datetime import datetime
import re
from functools import wraps

# Load variables from a local .env file (if present) into the environment,
# so LINE_CHANNEL_ACCESS_TOKEN / LINE_CHANNEL_SECRET / SECRET_KEY etc. don't
# need to be re-exported in every new terminal session. Safe to keep this
# even in production: if no .env file exists (e.g. on Render, which uses
# its own Environment tab), this is simply a no-op and real env vars set by
# the host still take priority.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_socketio import SocketIO, emit, join_room
from werkzeug.security import generate_password_hash, check_password_hash

BASE = Path(__file__).parent
# DB_PATH env var lets the database live outside the app folder - needed on
# hosts like Render where the app's own filesystem is wiped on every deploy,
# so the DB must sit on a mounted persistent disk instead (e.g. /var/data).
# Unset (the normal local case) it stays right next to app.py as before.
DB = Path(os.getenv("DB_PATH", str(BASE/"myhealthy.db")))
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# LINE Messaging API channel access token, set as an environment variable at
# deploy time (never in the DB or in source) - e.g.:
#   export LINE_CHANNEL_ACCESS_TOKEN="...."   (macOS/Linux)
#   $env:LINE_CHANNEL_ACCESS_TOKEN="...."     (Windows PowerShell)
# If this is unset, guardian-LINE push is simply skipped and the app falls
# back to the existing "teacher copies the approved message manually" flow -
# nothing else about the app changes or breaks.
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "").strip()
LINE_PUSH_URL = "https://api.line.me/v2/bot/message/push"
LINE_REPLY_URL = "https://api.line.me/v2/bot/message/reply"

# Channel *secret* (different from the access token above) - used only to
# verify that an incoming webhook request genuinely came from LINE, via the
# X-Line-Signature header. Never accept webhook bodies without this check:
# without it, anyone who finds the webhook URL could link arbitrary LINE
# accounts to arbitrary students.
LINE_CHANNEL_SECRET = os.getenv("LINE_CHANNEL_SECRET", "").strip()

def send_line_push(to_user_id, message):
    """Push a plain-text message to one LINE user via the Messaging API.
    Returns (ok: bool, detail: str). Never raises - a failed/unconfigured
    push must not break the approval flow, since the teacher can always
    fall back to sending the approved message manually."""
    if not LINE_CHANNEL_ACCESS_TOKEN:
        return False, "LINE_CHANNEL_ACCESS_TOKEN ยังไม่ได้ตั้งค่าบนเซิร์ฟเวอร์"
    if not to_user_id:
        return False, "ยังไม่มี LINE User ID ของผู้ปกครอง"
    body = json.dumps({
        "to": to_user_id,
        "messages": [{"type": "text", "text": message[:5000]}]
    }).encode("utf-8")
    req = urllib.request.Request(LINE_PUSH_URL, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + LINE_CHANNEL_ACCESS_TOKEN
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                return True, "sent"
            return False, f"LINE API ตอบกลับสถานะ {resp.status}"
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "ignore")[:300]
        return False, f"LINE API ผิดพลาด ({e.code}): {detail}"
    except Exception as e:
        return False, f"ส่งผ่าน LINE ไม่สำเร็จ: {e}"

def send_line_reply(reply_token, message):
    """Reply to a specific incoming LINE message (used by the webhook below).
    Unlike a push, a reply doesn't need a stored User ID - LINE gives us a
    one-time replyToken with the incoming event. Never raises, same reasoning
    as send_line_push. Silently no-ops if no token is configured or the event
    carried no replyToken (e.g. some non-message event types)."""
    if not LINE_CHANNEL_ACCESS_TOKEN or not reply_token:
        return False, "ไม่มี access token หรือ replyToken"
    body = json.dumps({
        "replyToken": reply_token,
        "messages": [{"type": "text", "text": message[:5000]}]
    }).encode("utf-8")
    req = urllib.request.Request(LINE_REPLY_URL, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + LINE_CHANNEL_ACCESS_TOKEN
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300, "sent"
    except Exception as e:
        return False, f"LINE reply ไม่สำเร็จ: {e}"

def verify_line_signature(raw_body: bytes, signature: str) -> bool:
    """Validate the X-Line-Signature header LINE sends with every webhook
    call: HMAC-SHA256 of the raw request body, keyed with the channel
    secret, base64-encoded. If LINE_CHANNEL_SECRET isn't configured we
    reject everything rather than silently accepting unverified webhooks."""
    if not LINE_CHANNEL_SECRET or not signature:
        return False
    mac = hmac.new(LINE_CHANNEL_SECRET.encode("utf-8"), raw_body, hashlib.sha256).digest()
    expected = base64.b64encode(mac).decode("utf-8")
    return hmac.compare_digest(expected, signature)

# Only these extensions may ever be served as static files from BASE.
# This keeps app.py / db_setup.py / myhealthy.db / requirements.txt / README.md
# from being downloadable by anyone who guesses the filename.
SAFE_STATIC_EXT = {".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
                    ".svg", ".ico", ".woff", ".woff2", ".webmanifest"}

OPEN_STATUSES = ("PENDING", "SCHEDULED", "ARRIVED")
CLOSED_STATUSES = ("COMPLETED", "REJECTED", "CANCELLED")

# Appointment times are school wall-clock times in Thailand.
# Store YYYY-MM-DDTHH:mm without device/browser timezone conversion.
def normalize_appointment_at(value):
    value = str(value or "").strip()
    if not value:
        return ""
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2})", value)
    if m:
        # Keep the selected wall-clock time exactly as entered.
        # This also handles legacy values with a timezone suffix by taking
        # the original displayed wall-clock portion.
        return m.group(1)
    return value[:16]



def conn():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def rows(sql, args=()):
    c = conn(); r = [dict(x) for x in c.execute(sql, args).fetchall()]; c.close(); return r

def setting(key, default=None):
    r = rows("SELECT value FROM settings WHERE key=?", (key,))
    return r[0]["value"] if r else default

def set_setting(key, value):
    c = conn()
    c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    c.commit(); c.close()

def auto_bootstrap_teacher():
    """On free hosting tiers the SQLite file is wiped every time the service
    sleeps/restarts, which also wipes the one teacher account + shared access
    code created via /api/bootstrap-teacher - forcing someone to re-run that
    API call by hand after every restart. If BOOTSTRAP_TEACHER_USERNAME /
    BOOTSTRAP_TEACHER_PASSWORD / BOOTSTRAP_TEACHER_ACCESS_CODE are set as
    environment variables, recreate that same account automatically here on
    every startup - but only when no teacher account exists yet, so this
    never overwrites a password/access code someone deliberately changed
    later via the app. No-ops entirely if the env vars aren't set, or if a
    teacher account already exists (e.g. a persistent disk kept it around)."""
    if rows("SELECT teacher_id FROM teacher_accounts LIMIT 1"):
        return
    username = os.getenv("BOOTSTRAP_TEACHER_USERNAME", "").strip()
    password = os.getenv("BOOTSTRAP_TEACHER_PASSWORD", "")
    access_code = os.getenv("BOOTSTRAP_TEACHER_ACCESS_CODE", "").strip()
    display_name = os.getenv("BOOTSTRAP_TEACHER_DISPLAY_NAME", "ครูห้องพยาบาล").strip()
    if not username or len(password) < 8 or len(access_code) < 4:
        return  # env vars unset or invalid - silently skip, same as before
    c = conn()
    c.execute("INSERT INTO teacher_accounts(username,password_hash,display_name) VALUES(?,?,?)",
               (username, generate_password_hash(password), display_name))
    c.commit(); c.close()
    set_setting("teacher_access_code_hash", generate_password_hash(access_code))
    print(f"Auto-bootstrapped teacher account '{username}' from environment variables.")

def auth(required=None):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    r = rows("SELECT * FROM sessions WHERE token=?", (token,))
    if not r or (required and r[0]["user_type"] != required):
        return None
    return r[0]

def require(kind):
    def deco(fn):
        @wraps(fn)
        def w(*a, **k):
            u = auth(kind)
            if not u:
                return jsonify(error="ไม่มีสิทธิ์เข้าถึง"), 401
            return fn(u, *a, **k)
        return w
    return deco

def audit(actor, action, entity, eid, detail=""):
    c = conn()
    c.execute("INSERT INTO audit_logs(actor_type,actor_id,action,entity_type,entity_id,detail) VALUES(?,?,?,?,?,?)",
               (actor["user_type"], actor["user_id"], action, entity, str(eid), detail))
    c.commit(); c.close()

def broadcast(event, data, student_id=None):
    socketio.emit(event, data, room="teachers")
    if student_id:
        socketio.emit(event, data, room=f"student:{student_id}")

# ---------- static files ----------

@app.get("/")
def home():
    # Serve the unified login page (role picker: student/teacher) at the
    # site root instead of hardcoding student.html, so teachers no longer
    # need to know to go to a separate URL. teacher.html/student.html are
    # still reachable directly (via the catch-all route below) for anyone
    # with them bookmarked.
    return send_from_directory(BASE, "index.html")

@app.get("/<path:p>")
def serve_file(p):
    # Whitelist-based static file serving. Anything not explicitly a
    # front-end asset (html/css/js/images/fonts) is rejected, so source
    # files and the database can never be downloaded through the browser.
    fp = (BASE / p).resolve()
    try:
        fp.relative_to(BASE.resolve())
    except ValueError:
        abort(404)
    if fp.suffix.lower() not in SAFE_STATIC_EXT or not fp.is_file():
        abort(404)
    return send_from_directory(BASE, p)

# ---------- auth ----------

@app.post("/api/student/login")
def student_login():
    d = request.get_json() or {}
    sid = str(d.get("studentId", "")).strip(); dob = d.get("dob", "")
    r = rows("SELECT * FROM students WHERE student_id=? AND dob=? AND is_active=1", (sid, dob))
    if not r:
        return jsonify(error="ข้อมูลเข้าสู่ระบบไม่ถูกต้อง"), 401
    token = secrets.token_urlsafe(32)
    c = conn(); c.execute("INSERT INTO sessions(token,user_type,user_id) VALUES(?,?,?)", (token, "student", sid)); c.commit(); c.close()
    return jsonify(token=token, studentId=sid, name=r[0]["name"], className=r[0]["class_name"])

@app.post("/api/teacher/login")
def teacher_login():
    d = request.get_json() or {}
    u = str(d.get("username", "")).strip(); pw = d.get("password", "")
    code = str(d.get("accessCode", "")).strip()
    code_hash = setting("teacher_access_code_hash")
    if not code_hash or not check_password_hash(code_hash, code):
        return jsonify(error="รหัสเข้าใช้งานพิเศษไม่ถูกต้อง"), 401
    r = rows("SELECT * FROM teacher_accounts WHERE username=? AND is_active=1", (u,))
    if not r or not check_password_hash(r[0]["password_hash"], pw):
        return jsonify(error="รหัสครูไม่ถูกต้อง"), 401
    token = secrets.token_urlsafe(32)
    c = conn(); c.execute("INSERT INTO sessions(token,user_type,user_id) VALUES(?,?,?)", (token, "teacher", str(r[0]["teacher_id"]))); c.commit(); c.close()
    return jsonify(token=token, name=r[0]["display_name"])

@app.post("/api/logout")
def logout():
    u = auth()
    if u:
        c = conn(); c.execute("DELETE FROM sessions WHERE token=?", (u["token"],)); c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/api/bootstrap-teacher")
def bootstrap():
    # Only works while there is no teacher account yet. Also sets the shared
    # "access code" that must be entered on every teacher login, on top of
    # username/password, so students who see a teacher typing their password
    # over their shoulder still can't get in without the code the school
    # keeps separately.
    if rows("SELECT teacher_id FROM teacher_accounts LIMIT 1"):
        return jsonify(error="ตั้งค่าบัญชีแล้ว"), 403
    d = request.get_json() or {}
    username = str(d.get("username", "teacher")).strip()
    password = d.get("password", "")
    access_code = str(d.get("accessCode", "")).strip()
    if len(password) < 8:
        return jsonify(error="รหัสผ่านอย่างน้อย 8 ตัวอักษร"), 400
    if len(access_code) < 4:
        return jsonify(error="รหัสเข้าใช้งานพิเศษอย่างน้อย 4 ตัวอักษร"), 400
    c = conn()
    c.execute("INSERT INTO teacher_accounts(username,password_hash,display_name) VALUES(?,?,?)",
               (username, generate_password_hash(password), d.get("displayName", "ครูห้องพยาบาล")))
    c.commit(); c.close()
    set_setting("teacher_access_code_hash", generate_password_hash(access_code))
    return jsonify(ok=True, message="สร้างบัญชีครูสำเร็จ")

@app.post("/api/teacher/access-code")
@require("teacher")
def rotate_access_code(user):
    # Lets an existing teacher rotate the shared access code (e.g. every
    # semester, or immediately if it may have leaked) without needing
    # server/file access.
    d = request.get_json() or {}
    current_password = d.get("currentPassword", "")
    new_code = str(d.get("newAccessCode", "")).strip()
    row = rows("SELECT password_hash FROM teacher_accounts WHERE teacher_id=?", (user["user_id"],))
    if not row or not check_password_hash(row[0]["password_hash"], current_password):
        return jsonify(error="รหัสผ่านปัจจุบันไม่ถูกต้อง"), 401
    if len(new_code) < 4:
        return jsonify(error="รหัสเข้าใช้งานพิเศษอย่างน้อย 4 ตัวอักษร"), 400
    set_setting("teacher_access_code_hash", generate_password_hash(new_code))
    audit(user, "ROTATE_ACCESS_CODE", "settings", "teacher_access_code_hash")
    return jsonify(ok=True)

# ---------- appointments ----------

@app.get("/api/requests")
@require("teacher")
def teacher_requests(user):
    status = request.args.get("status")
    sql = """SELECT a.*,s.name,s.class_name,s.allergies FROM appointments a JOIN students s ON s.student_id=a.student_id"""
    args = []
    statuses = []
    if status:
        statuses = [s.strip() for s in status.split(",") if s.strip()]
        sql += " WHERE a.status IN (%s)" % ",".join("?" * len(statuses))
        args.extend(statuses)
    # The open queue (PENDING/SCHEDULED/ARRIVED) should triage by severity
    # first so the most urgent case is always on top. But that same rule
    # applied to the CLOSED history tab (COMPLETED/REJECTED/CANCELLED) meant
    # a high-severity case stayed pinned at the top forever, and ties broke
    # on created_at (when the case was first opened) instead of when it was
    # actually closed - so a case closed just now could still land in the
    # middle of the list. History should simply read most-recently-closed
    # first, so use closed_at there instead of the severity/created_at rule.
    if statuses and all(s in CLOSED_STATUSES for s in statuses):
        sql += " ORDER BY a.closed_at DESC, a.appointment_id DESC"
    else:
        sql += " ORDER BY CASE a.severity WHEN 'มาก' THEN 1 WHEN 'กลาง' THEN 2 ELSE 3 END,a.created_at DESC"
    out = rows(sql, args)
    for x in out:
        x["tags"] = json.loads(x.pop("symptoms_json"))
    # Attach whatever was actually dispensed for each case. This was tracked
    # in appointment_medicines from the start (complete() already inserts
    # into it), but /api/requests never selected it back out - so a closed
    # case's medicine never had anywhere to surface in the teacher UI, even
    # though it was sitting in the database the whole time.
    if out:
        ids = [x["appointment_id"] for x in out]
        meds_by_appt = {}
        for m in rows("""SELECT appointment_id,medicine_name_snapshot,dosage_instruction
                          FROM appointment_medicines WHERE appointment_id IN (%s)
                          ORDER BY id""" % ",".join("?" * len(ids)), ids):
            meds_by_appt.setdefault(m["appointment_id"], []).append(
                {"name": m["medicine_name_snapshot"], "instruction": m["dosage_instruction"]})
        for x in out:
            x["medicines"] = meds_by_appt.get(x["appointment_id"], [])
    return jsonify(out)

@app.get("/api/my/requests")
@require("student")
def my_requests(user):
    # Always put the student's current scheduled/arrived appointment first.
    # This is important because the student UI may use the first OPEN case as
    # its current case. Without this ordering, an older PENDING row can hide
    # the appointment that the teacher has just scheduled.
    #
    # A case is considered the current case only while it is OPEN and has an
    # appointment time. COMPLETED/CANCELLED/REJECTED rows remain history and
    # can never take the current-case position.
    out = rows("""
        SELECT *
        FROM appointments
        WHERE student_id=?
        ORDER BY
            CASE
                WHEN status IN ('SCHEDULED','ARRIVED')
                     AND appointment_at IS NOT NULL
                     AND TRIM(appointment_at) <> ''
                THEN 0
                WHEN status='PENDING' THEN 1
                ELSE 2
            END,
            CASE
                WHEN status IN ('SCHEDULED','ARRIVED')
                     AND appointment_at IS NOT NULL
                     AND TRIM(appointment_at) <> ''
                THEN appointment_at
                ELSE NULL
            END DESC,
            appointment_id DESC
    """, (user["user_id"],))
    for x in out:
        x["tags"] = json.loads(x.pop("symptoms_json"))
    return jsonify(out)

@app.post("/api/request")
@require("student")
def create_request(user):
    d = request.get_json() or {}
    raw_tags = d.get("tags", [])
    details = str(d.get("details", ""))[:1000]; sev = d.get("severity")
    # Defense in depth: the front end only ever sends short strings picked
    # from a fixed symptom list, but nothing stops a client from calling
    # this endpoint directly with something else (e.g. HTML/script content
    # meant to run in the teacher's browser once rendered in the queue).
    # Force every tag to a short, plain string so nothing but ordinary text
    # ever reaches the database or gets rendered on the teacher/student UI.
    if not isinstance(raw_tags, list):
        return jsonify(error="รูปแบบอาการไม่ถูกต้อง"), 400
    tags = [str(t).strip()[:60] for t in raw_tags if str(t).strip()][:20]
    if not tags and not details:
        return jsonify(error="กรุณาระบุอาการ"), 400
    if sev not in ("น้อย", "กลาง", "มาก"):
        return jsonify(error="ระดับความรุนแรงไม่ถูกต้อง"), 400
    # A student may only have ONE open case (PENDING/SCHEDULED/ARRIVED) at a
    # time. Without this guard, an anxious/impatient student who reports
    # again while waiting creates a second row - and since the student page
    # always showed whatever row was created most recently, a teacher
    # scheduling the OLDER (real) case would silently stop appearing on the
    # student's screen, because the newer still-PENDING row (with no
    # appointment_at yet) covered it. This was the root cause of "the
    # appointment time doesn't update on the student side".
    if rows("SELECT appointment_id FROM appointments WHERE student_id=? AND status IN (%s)" %
            ",".join("?" * len(OPEN_STATUSES)), (user["user_id"], *OPEN_STATUSES)):
        return jsonify(error="คุณมีคำขอที่ยังไม่เสร็จสิ้นอยู่แล้ว กรุณารอการตอบกลับ หรือยกเลิกคำขอเดิมก่อนส่งใหม่"), 409
    c = conn()
    cur = c.execute("INSERT INTO appointments(student_id,symptoms_json,details,severity) VALUES(?,?,?,?)",
                     (user["user_id"], json.dumps(tags, ensure_ascii=False), details, sev))
    aid = cur.lastrowid; c.commit(); c.close()
    audit(user, "CREATE", "appointment", aid)
    broadcast("queue_update", {"type": "new", "id": aid}, user["user_id"])
    return jsonify(id=aid, status="PENDING"), 201

@app.post("/api/appointment/<int:aid>/cancel")
@require("student")
def cancel_request(user, aid):
    # A student may withdraw their own request, but only while it's still
    # PENDING - once a teacher has scheduled or seen them it must be handled
    # by the teacher (reject) instead, so nothing quietly disappears mid-flow.
    c = conn()
    r = c.execute("SELECT student_id,status FROM appointments WHERE appointment_id=?", (aid,)).fetchone()
    if not r or r["student_id"] != user["user_id"]:
        c.close(); return jsonify(error="ไม่พบเคส"), 404
    if r["status"] != "PENDING":
        c.close(); return jsonify(error="ไม่สามารถยกเลิกได้ในสถานะนี้"), 400
    c.execute("UPDATE appointments SET status='CANCELLED',closed_at=CURRENT_TIMESTAMP WHERE appointment_id=?", (aid,))
    c.commit(); c.close()
    audit(user, "CANCEL", "appointment", aid)
    broadcast("queue_update", {"type": "cancelled", "id": aid}, user["user_id"])
    return jsonify(ok=True)

@app.get("/api/diagnose")
@require("teacher")
def diagnose(user):
    tags = [x.strip() for x in request.args.get("tags", "").split(",") if x.strip()]
    if not tags:
        return jsonify(assessments=[], warning="ไม่มีข้อมูลอาการ")
    q = ("SELECT preliminary_assessment,MIN(priority) AS pr FROM symptom_rules "
         "WHERE symptom IN (%s) GROUP BY preliminary_assessment ORDER BY pr,preliminary_assessment" % ",".join("?" * len(tags)))
    assessments = [x["preliminary_assessment"] for x in rows(q, tags)]
    return jsonify(assessments=assessments, disclaimer="เป็นระบบช่วยประเมินเบื้องต้น ครู/บุคลากรต้องตรวจสอบก่อนดำเนินการ")

@app.post("/api/appointment/<int:aid>/schedule")
@require("teacher")
def schedule(user, aid):
    d = request.get_json() or {}; when = normalize_appointment_at(d.get("appointmentAt", ""))
    if not when:
        return jsonify(error="กรุณาระบุเวลานัด"), 400
    c = conn()
    r = c.execute("SELECT student_id,status FROM appointments WHERE appointment_id=?", (aid,)).fetchone()
    if not r:
        c.close(); return jsonify(error="ไม่พบเคส"), 404
    if r["status"] in ("COMPLETED", "CANCELLED", "REJECTED"):
        c.close(); return jsonify(error="เคสนี้ปิดแล้ว"), 400
    c.execute("UPDATE appointments SET status='SCHEDULED',appointment_at=?,preliminary_assessment=?,teacher_notes=?,updated_at=CURRENT_TIMESTAMP WHERE appointment_id=?",
               (when, str(d.get("assessment", ""))[:500], str(d.get("notes", ""))[:1000], aid))
    c.commit(); c.close()
    audit(user, "SCHEDULE", "appointment", aid)
    broadcast("appointment_update", {"id": aid, "status": "SCHEDULED"}, r["student_id"])
    return jsonify(ok=True)

@app.post("/api/appointment/<int:aid>/arrive")
@require("teacher")
def arrive(user, aid):
    c = conn()
    r = c.execute("SELECT student_id,status FROM appointments WHERE appointment_id=?", (aid,)).fetchone()
    if not r:
        c.close(); return jsonify(error="ไม่พบเคส"), 404
    if r["status"] in ("COMPLETED", "CANCELLED", "REJECTED"):
        c.close(); return jsonify(error="เคสนี้ปิดแล้ว"), 400
    c.execute("UPDATE appointments SET status='ARRIVED',updated_at=CURRENT_TIMESTAMP WHERE appointment_id=?", (aid,))
    c.commit(); c.close()
    audit(user, "ARRIVE", "appointment", aid)
    broadcast("appointment_update", {"id": aid, "status": "ARRIVED"}, r["student_id"])
    return jsonify(ok=True)

@app.post("/api/appointment/<int:aid>/reject")
@require("teacher")
def reject(user, aid):
    # For false alarms / duplicates / cases handled outside the system, so
    # they don't sit in the PENDING queue forever.
    d = request.get_json() or {}; reason = str(d.get("reason", ""))[:500]
    c = conn()
    r = c.execute("SELECT student_id,status FROM appointments WHERE appointment_id=?", (aid,)).fetchone()
    if not r:
        c.close(); return jsonify(error="ไม่พบเคส"), 404
    if r["status"] in ("COMPLETED", "CANCELLED", "REJECTED"):
        c.close(); return jsonify(error="เคสนี้ปิดแล้ว"), 400
    c.execute("UPDATE appointments SET status='REJECTED',close_reason=?,closed_at=CURRENT_TIMESTAMP WHERE appointment_id=?", (reason, aid))
    c.commit(); c.close()
    audit(user, "REJECT", "appointment", aid, reason)
    broadcast("appointment_update", {"id": aid, "status": "REJECTED"}, r["student_id"])
    return jsonify(ok=True)

@app.post("/api/appointment/<int:aid>/complete")
@require("teacher")
def complete(user, aid):
    d = request.get_json() or {}; meds = d.get("medicines", [])
    if not isinstance(meds, list):
        return jsonify(error="รูปแบบยาไม่ถูกต้อง"), 400
    c = conn()
    r = c.execute("SELECT student_id,details,symptoms_json,status FROM appointments WHERE appointment_id=?", (aid,)).fetchone()
    if not r:
        c.close(); return jsonify(error="ไม่พบเคส"), 404
    if r["status"] in ("COMPLETED", "CANCELLED", "REJECTED"):
        c.close(); return jsonify(error="เคสนี้ปิดแล้ว"), 400
    allergies = rows("SELECT allergies FROM students WHERE student_id=?", (r["student_id"],))[0]["allergies"]
    c.execute("UPDATE appointments SET status='COMPLETED',closed_at=CURRENT_TIMESTAMP WHERE appointment_id=?", (aid,))
    given_names = []
    for m in meds:
        name = str(m.get("name", "")).strip()
        if name:
            c.execute("INSERT INTO appointment_medicines(appointment_id,medicine_name_snapshot,dosage_instruction,dispensed_by,dispensed_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)",
                       (aid, name, str(m.get("instruction", ""))[:500], user["user_id"]))
            given_names.append(name)
    symptoms = ", ".join(json.loads(r["symptoms_json"]))
    # The dispensed medicine list was built above but never made it into the
    # guardian message - a teacher could pick a medicine, close the case, and
    # the resulting notification would say nothing about what was given.
    meds_line = f" ได้รับยา: {', '.join(given_names)}." if given_names else ""
    msg = f"นักเรียนเข้ารับบริการห้องพยาบาล เนื่องจากมีอาการ: {symptoms or r['details']}.{meds_line} ได้รับการดูแลเรียบร้อยแล้ว"
    c.execute("INSERT INTO notifications(appointment_id,recipient_type,message,status) VALUES(?,?,?,?)",
               (aid, "GUARDIAN", msg, "PENDING_APPROVAL"))
    c.commit(); c.close()
    audit(user, "COMPLETE", "appointment", aid)
    broadcast("appointment_update", {"id": aid, "status": "COMPLETED"}, r["student_id"])
    return jsonify(ok=True, guardianMessage=msg, allergyNote=allergies)

# ---------- notifications (the "pending approval" queue actually surfaced) ----------

@app.get("/api/notifications")
@require("teacher")
def list_notifications(user):
    status = request.args.get("status", "PENDING_APPROVAL")
    out = rows("""SELECT n.*,s.name,s.class_name,s.guardian_name,s.guardian_contact,s.guardian_line_user_id
                  FROM notifications n
                  JOIN appointments a ON a.appointment_id=n.appointment_id
                  JOIN students s ON s.student_id=a.student_id
                  WHERE n.status=? ORDER BY n.created_at DESC""", (status,))
    return jsonify(out)

@app.post("/api/notifications/<int:nid>/approve")
@require("teacher")
def approve_notification(user, nid):
    # Teacher reviews (and may edit) the auto-drafted message. Approving it
    # tries to push it to the guardian's LINE immediately; if that isn't
    # possible (no LINE User ID on file yet, token not configured, or the
    # LINE API call fails) the message is still marked approved/SENT and the
    # teacher falls back to sending it manually through whatever channel the
    # school uses - approval never silently fails just because LINE did.
    d = request.get_json() or {}
    message = str(d.get("message", "")).strip()
    r = rows("""SELECT n.*,s.guardian_line_user_id FROM notifications n
                JOIN appointments a ON a.appointment_id=n.appointment_id
                JOIN students s ON s.student_id=a.student_id
                WHERE n.notification_id=?""", (nid,))
    if not r:
        return jsonify(error="ไม่พบข้อความ"), 404
    if r[0]["status"] != "PENDING_APPROVAL":
        return jsonify(error="ข้อความนี้ถูกดำเนินการแล้ว"), 400
    final_message = message[:1000] if message else r[0]["message"]

    line_ok, line_detail = send_line_push(r[0]["guardian_line_user_id"], final_message)
    channel = "LINE" if line_ok else "MANUAL"

    c = conn()
    c.execute("""UPDATE notifications SET message=?,status='SENT',sent_at=CURRENT_TIMESTAMP,
                 approved_by=?,channel=? WHERE notification_id=?""",
               (final_message, user["user_id"], channel, nid))
    c.commit(); c.close()
    audit(user, "APPROVE", "notification", nid, detail=f"channel={channel}; {line_detail}")
    return jsonify(ok=True, lineSent=line_ok, lineDetail=line_detail)

@app.post("/api/notifications/<int:nid>/reject")
@require("teacher")
def reject_notification(user, nid):
    d = request.get_json() or {}; reason = str(d.get("reason", ""))[:500]
    r = rows("SELECT status FROM notifications WHERE notification_id=?", (nid,))
    if not r:
        return jsonify(error="ไม่พบข้อความ"), 404
    if r[0]["status"] != "PENDING_APPROVAL":
        return jsonify(error="ข้อความนี้ถูกดำเนินการแล้ว"), 400
    c = conn()
    c.execute("UPDATE notifications SET status='CANCELLED',reject_reason=? WHERE notification_id=?", (reason, nid))
    c.commit(); c.close()
    audit(user, "REJECT", "notification", nid, reason)
    return jsonify(ok=True)

# ---------- students & medicines ----------

@app.get("/api/student/<sid>")
@require("teacher")
def student(user, sid):
    r = rows("SELECT student_id,name,class_name,dob,allergies,guardian_name,guardian_contact,guardian_line_user_id FROM students WHERE student_id=?", (sid,))
    return (jsonify(r[0]), 200) if r else (jsonify(error="ไม่พบข้อมูล"), 404)

@app.post("/api/student/<sid>/line")
@require("teacher")
def set_guardian_line(user, sid):
    # Manual linking: the school has parents add the school's LINE OA and
    # send their LINE User ID in, and a teacher pastes it in here once. This
    # app has no LINE Login flow of its own, so this is the deliberate,
    # explicit way a guardian gets connected - never inferred or guessed.
    d = request.get_json() or {}
    line_id = str(d.get("lineUserId", "")).strip()[:64]
    if not rows("SELECT 1 FROM students WHERE student_id=?", (sid,)):
        return jsonify(error="ไม่พบข้อมูลนักเรียน"), 404
    c = conn(); c.execute("UPDATE students SET guardian_line_user_id=? WHERE student_id=?", (line_id, sid)); c.commit(); c.close()
    audit(user, "SET_GUARDIAN_LINE", "student", sid)
    return jsonify(ok=True)

@app.post("/api/line/webhook")
def line_webhook():
    # Self-service alternative to the manual "teacher pastes in the User ID"
    # flow above: a guardian messages the school's LINE OA with their
    # child's student ID and date of birth (the same two facts that gate
    # student login), and this webhook links their LINE account
    # automatically - no teacher involvement needed.
    #
    # Signature verification is mandatory, not optional: without it, anyone
    # who discovers this URL could POST fake events and link an arbitrary
    # LINE account to an arbitrary student, letting that account both read
    # what the school sends about that student and appear to be the parent
    # of a child that isn't theirs. If LINE_CHANNEL_SECRET isn't configured,
    # every request is rejected rather than trusted.
    raw = request.get_data()
    if not verify_line_signature(raw, request.headers.get("X-Line-Signature", "")):
        abort(403)
    payload = request.get_json(silent=True) or {}
    for ev in payload.get("events", []):
        if ev.get("type") == "follow":
            # Guardian just added the school's OA for the first time - give
            # them the instructions up front instead of leaving them to
            # guess what to send.
            send_line_reply(ev.get("replyToken"),
                "สวัสดีค่ะ/ครับ 👋 ยินดีต้อนรับสู่ระบบแจ้งเตือนห้องพยาบาล\n\n"
                "กรุณาพิมพ์ เลขประจำตัวนักเรียน และ วันเกิด ของบุตรหลาน คั่นด้วยเว้นวรรค เพื่อผูกบัญชี LINE นี้ไว้รับการแจ้งเตือน\n"
                "รูปแบบ: เลขประจำตัวนักเรียน ปปปป-ดด-วว\nตัวอย่าง: 12345 2010-05-15")
            continue
        if ev.get("type") != "message" or ev.get("message", {}).get("type") != "text":
            continue
        reply_token = ev.get("replyToken")
        line_user_id = (ev.get("source") or {}).get("userId", "")
        text = str(ev.get("message", {}).get("text", "")).strip()
        parts = text.replace(",", " ").split()
        if len(parts) != 2:
            send_line_reply(reply_token,
                "กรุณาส่งข้อความในรูปแบบ: เลขประจำตัวนักเรียน วันเกิด(ปปปป-ดด-วว)\n"
                "เช่น 12345 2010-05-15")
            continue
        sid, dob = parts[0].strip(), parts[1].strip()
        student = rows("SELECT student_id,name FROM students WHERE student_id=? AND dob=? AND is_active=1", (sid, dob))
        if not student:
            send_line_reply(reply_token,
                "ไม่พบข้อมูลนักเรียนที่ตรงกับเลขประจำตัว/วันเกิดที่ระบุ กรุณาตรวจสอบอีกครั้ง "
                "หรือติดต่อครูห้องพยาบาลของโรงเรียน")
            continue
        if not line_user_id:
            continue
        c = conn()
        c.execute("UPDATE students SET guardian_line_user_id=? WHERE student_id=?", (line_user_id, sid))
        c.commit(); c.close()
        audit({"user_type": "system", "user_id": "line-webhook"}, "SET_GUARDIAN_LINE", "student", sid,
              detail="self-service ผูกผ่าน LINE OA")
        send_line_reply(reply_token,
            f"เชื่อมต่อสำเร็จ ✅ ผูกบัญชี LINE นี้กับนักเรียน {student[0]['name']} เรียบร้อยแล้ว "
            "ทางโรงเรียนจะแจ้งข้อมูลผ่าน LINE นี้เมื่อมีการอัปเดตอาการของนักเรียน")
    return jsonify(ok=True)

@app.get("/api/students")
@require("teacher")
def list_students(user):
    # Full active-student roster for the "รายชื่อนักเรียน" tab, so a teacher
    # can link a guardian's LINE User ID up front instead of waiting for
    # that student's first appointment to open the case modal.
    return jsonify(rows("""SELECT student_id,name,class_name,guardian_name,guardian_contact,guardian_line_user_id
                            FROM students WHERE is_active=1 ORDER BY class_name,name"""))

# ---------- symptoms (canonical list, used to tag medicines unambiguously) ----------

@app.get("/api/symptoms")
@require(None)
def symptoms_list(user):
    # Open to both roles (not just teacher): students need this same list to
    # report symptoms, so the two sides never drift apart the way a
    # hardcoded copy in student.html used to risk.
    return jsonify([r["symptom"] for r in rows("SELECT symptom FROM symptoms ORDER BY rowid")])

@app.post("/api/symptoms")
@require("teacher")
def add_symptom(user):
    # Lets a teacher extend the canonical symptom list on the fly (e.g. a
    # symptom that keeps coming up but isn't one of the original 10) instead
    # of needing someone to edit db_setup.py and redeploy. Newly added
    # symptoms immediately become available both for tagging medicines here
    # and for students to pick when reporting - same table, same endpoint.
    d = request.get_json() or {}
    name = str(d.get("symptom", "")).strip()
    if not name:
        return jsonify(error="กรุณาระบุชื่ออาการ"), 400
    if len(name) > 50:
        return jsonify(error="ชื่ออาการยาวเกินไป"), 400
    c = conn()
    try:
        c.execute("INSERT INTO symptoms(symptom) VALUES(?)", (name,))
        c.commit()
    except sqlite3.IntegrityError:
        c.close(); return jsonify(error="มีอาการนี้อยู่แล้ว"), 409
    c.close()
    audit(user, "CREATE", "symptom", name)
    return jsonify(ok=True), 201

@app.get("/api/medicines")
@require("teacher")
def medicines(user):
    meds = rows("SELECT medicine_id,medicine_name,description,active FROM medicines WHERE active=1 ORDER BY medicine_name")
    tags = rows("SELECT medicine_id,symptom FROM medicine_symptoms")
    by_med = {}
    for t in tags:
        by_med.setdefault(t["medicine_id"], []).append(t["symptom"])
    for m in meds:
        m["symptoms"] = by_med.get(m["medicine_id"], [])
    return jsonify(meds)

def _set_medicine_symptoms(c, mid, symptom_list):
    # Only symptoms that exist in the canonical `symptoms` table are ever
    # stored - anything else (typo, free text someone slipped past the UI)
    # is silently dropped rather than creating a new, uncontrolled tag.
    valid = {r[0] for r in c.execute("SELECT symptom FROM symptoms").fetchall()}
    clean = sorted({s for s in symptom_list if s in valid})
    c.execute("DELETE FROM medicine_symptoms WHERE medicine_id=?", (mid,))
    c.executemany("INSERT INTO medicine_symptoms(medicine_id,symptom) VALUES(?,?)", [(mid, s) for s in clean])
    return clean

@app.post("/api/medicines")
@require("teacher")
def add_medicine(user):
    d = request.get_json() or {}
    name = str(d.get("name", "")).strip()
    raw_symptoms = d.get("symptoms", [])
    if not name:
        return jsonify(error="กรุณาระบุชื่อยา"), 400
    if not isinstance(raw_symptoms, list):
        return jsonify(error="รูปแบบอาการไม่ถูกต้อง"), 400
    c = conn()
    try:
        cur = c.execute("INSERT INTO medicines(medicine_name,description) VALUES(?,?)", (name, str(d.get("description", ""))[:300]))
        mid = cur.lastrowid
        clean = _set_medicine_symptoms(c, mid, raw_symptoms)
        c.commit()
    except sqlite3.IntegrityError:
        c.close(); return jsonify(error="มีรายการยานี้อยู่แล้ว"), 409
    c.close()
    audit(user, "CREATE", "medicine", name, detail=", ".join(clean))
    return jsonify(ok=True), 201

@app.post("/api/medicines/<int:mid>/symptoms")
@require("teacher")
def update_medicine_symptoms(user, mid):
    # Lets a teacher retag an existing medicine's matched symptoms without
    # deleting and recreating it (which would also orphan its dispensing
    # history in appointment_medicines).
    d = request.get_json() or {}
    raw_symptoms = d.get("symptoms", [])
    if not isinstance(raw_symptoms, list):
        return jsonify(error="รูปแบบอาการไม่ถูกต้อง"), 400
    if not rows("SELECT 1 FROM medicines WHERE medicine_id=?", (mid,)):
        return jsonify(error="ไม่พบรายการยา"), 404
    c = conn()
    clean = _set_medicine_symptoms(c, mid, raw_symptoms)
    c.commit(); c.close()
    audit(user, "UPDATE_SYMPTOMS", "medicine", mid, detail=", ".join(clean))
    return jsonify(ok=True, symptoms=clean)

@app.post("/api/medicines/<int:mid>/deactivate")
@require("teacher")
def deactivate_medicine(user, mid):
    c = conn(); c.execute("UPDATE medicines SET active=0 WHERE medicine_id=?", (mid,)); c.commit(); c.close()
    audit(user, "DEACTIVATE", "medicine", mid)
    return jsonify(ok=True)

# ---------- websocket ----------

@socketio.on("connect")
def ws_connect(auth_data):
    token = (auth_data or {}).get("token", "")
    r = rows("SELECT * FROM sessions WHERE token=?", (token,))
    if not r:
        return False
    join_room("teachers" if r[0]["user_type"] == "teacher" else f"student:{r[0]['user_id']}")
    emit("connected", {"ok": True})

if __name__ == "__main__":
    if not DB.exists():
        print("ERROR: Run 'python db_setup.py' first."); raise SystemExit(1)
    auto_bootstrap_teacher()
    port = int(os.getenv("PORT", 5000))
    print(f"MyHealthy: http://localhost:{port}")
    # Newer Werkzeug (3.1+) refuses to run its dev server outside debug mode
    # unless explicitly told to. This app is meant to run on a school's own
    # LAN (not exposed to the internet), so the built-in server is fine here;
    # allow_unsafe_werkzeug silences that guard instead of the app crashing
    # on startup with recent dependency versions. On a host like Render,
    # PORT is injected by the platform and must be what we bind to - a
    # hardcoded port will fail health checks there.
    socketio.run(app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True)
