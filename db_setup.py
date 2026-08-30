import sqlite3, os
from pathlib import Path

# Same DB_PATH override as app.py - keep both in sync so db_setup.py
# initializes the exact file app.py will read/write on hosts like Render
# where the DB must live on a mounted persistent disk, not next to the code.
DB_PATH = Path(os.getenv("DB_PATH", str(Path(__file__).with_name("myhealthy.db"))))

SCHEMA = """
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS students (
 student_id TEXT PRIMARY KEY, name TEXT NOT NULL, class_name TEXT,
 dob TEXT NOT NULL, allergies TEXT DEFAULT '', guardian_name TEXT,
 guardian_contact TEXT DEFAULT '', is_active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS teacher_accounts (
 teacher_id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, display_name TEXT NOT NULL, is_active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY, user_type TEXT NOT NULL, user_id TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS appointments (
 appointment_id INTEGER PRIMARY KEY AUTOINCREMENT, student_id TEXT NOT NULL,
 symptoms_json TEXT NOT NULL DEFAULT '[]', details TEXT DEFAULT '',
 severity TEXT NOT NULL,
 -- status lifecycle: PENDING -> SCHEDULED -> ARRIVED -> COMPLETED
 --                             or REJECTED   (teacher closes false alarm / duplicate)
 --                    PENDING -> CANCELLED   (student cancels their own request)
 status TEXT NOT NULL DEFAULT 'PENDING',
 appointment_at TEXT, preliminary_assessment TEXT DEFAULT '',
 teacher_notes TEXT DEFAULT '', close_reason TEXT DEFAULT '',
 closed_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(student_id) REFERENCES students(student_id)
);
CREATE TABLE IF NOT EXISTS medicines (
 medicine_id INTEGER PRIMARY KEY AUTOINCREMENT, medicine_name TEXT UNIQUE NOT NULL,
 description TEXT DEFAULT '', active INTEGER DEFAULT 1
);
-- Canonical symptom list. Kept as its own table (rather than free text) so
-- the "add medicine" screen can only ever tag a medicine with a symptom that
-- actually exists in the student-facing tag list - no typos, no near-duplicate
-- symptom names splitting the same medicine across two spellings.
CREATE TABLE IF NOT EXISTS symptoms (
 symptom TEXT PRIMARY KEY
);
-- Many-to-many: one medicine can cover several symptoms, one symptom can be
-- covered by several medicines. This is what powers "which medicines fit
-- this case" in the teacher UI.
CREATE TABLE IF NOT EXISTS medicine_symptoms (
 medicine_id INTEGER NOT NULL, symptom TEXT NOT NULL,
 PRIMARY KEY (medicine_id, symptom),
 FOREIGN KEY(medicine_id) REFERENCES medicines(medicine_id),
 FOREIGN KEY(symptom) REFERENCES symptoms(symptom)
);
CREATE TABLE IF NOT EXISTS appointment_medicines (
 id INTEGER PRIMARY KEY AUTOINCREMENT, appointment_id INTEGER NOT NULL,
 medicine_name_snapshot TEXT NOT NULL, dosage_instruction TEXT DEFAULT '',
 dispensed_by TEXT DEFAULT '', dispensed_at TEXT,
 FOREIGN KEY(appointment_id) REFERENCES appointments(appointment_id)
);
CREATE TABLE IF NOT EXISTS symptom_rules (
 rule_id INTEGER PRIMARY KEY AUTOINCREMENT, symptom TEXT NOT NULL,
 preliminary_assessment TEXT NOT NULL, priority INTEGER DEFAULT 0,
 UNIQUE(symptom, preliminary_assessment)
);
CREATE TABLE IF NOT EXISTS notifications (
 notification_id INTEGER PRIMARY KEY AUTOINCREMENT, appointment_id INTEGER NOT NULL,
 recipient_type TEXT NOT NULL, channel TEXT DEFAULT 'PENDING_APPROVAL',
 message TEXT NOT NULL, status TEXT DEFAULT 'PENDING_APPROVAL', sent_at TEXT,
 approved_by TEXT, reject_reason TEXT DEFAULT '',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(appointment_id) REFERENCES appointments(appointment_id)
);
CREATE TABLE IF NOT EXISTS audit_logs (
 log_id INTEGER PRIMARY KEY AUTOINCREMENT, actor_type TEXT NOT NULL, actor_id TEXT,
 action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT, detail TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
-- key/value store for things like the shared teacher access-code hash
CREATE TABLE IF NOT EXISTS settings (
 key TEXT PRIMARY KEY, value TEXT
);

CREATE INDEX IF NOT EXISTS idx_appointments_status  ON appointments(status);
CREATE INDEX IF NOT EXISTS idx_appointments_student  ON appointments(student_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user         ON sessions(user_type,user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_status  ON notifications(status);
CREATE INDEX IF NOT EXISTS idx_symptom_rules_symptom ON symptom_rules(symptom);
CREATE INDEX IF NOT EXISTS idx_medicine_symptoms_symptom ON medicine_symptoms(symptom);
"""

# The exact 10 symptoms students can pick from in student.html. Kept as a
# single source of truth here so the medicine-tagging checkboxes in the
# teacher UI can never drift out of sync with what students actually submit.
# If you ever add a symptom to student.html's `symptoms` list, add it here too.
CANONICAL_SYMPTOMS = ['ปวดหัว','ตัวร้อน','มีไข้','ปวดท้อง','ท้องเสีย','เจ็บคอ','ไอ','เวียนหัว','ผื่นคัน','บาดเจ็บ/มีแผล']

def migrate_columns(conn):
    """Add columns to existing tables that predate this version of the schema,
    without touching data already in them. sqlite has no
    'ADD COLUMN IF NOT EXISTS', so check pragma table_info first."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(students)").fetchall()}
    if "guardian_line_user_id" not in cols:
        conn.execute("ALTER TABLE students ADD COLUMN guardian_line_user_id TEXT DEFAULT ''")

def main():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    migrate_columns(conn)

    # NOTE: notifications.status used to default to 'PENDING'; the app now uses
    # 'PENDING_APPROVAL' consistently. Migrate any old rows quietly if this DB
    # already existed from a previous version.
    conn.execute("UPDATE notifications SET status='PENDING_APPROVAL' WHERE status='PENDING'")

    conn.executemany("""INSERT OR IGNORE INTO students
      (student_id,name,class_name,dob,allergies,guardian_name,guardian_contact)
      VALUES (?,?,?,?,?,?,?)""", [
      ("12345", "นักเรียนตัวอย่าง 1", "ม.4/1", "2010-05-15", "ไม่มีข้อมูลแพ้ยา", "ผู้ปกครองตัวอย่าง", ""),
      ("67890", "นักเรียนตัวอย่าง 2", "ม.5/1", "2009-11-20", "Penicillin", "ผู้ปกครองตัวอย่าง", "")
    ])
    conn.executemany("INSERT OR IGNORE INTO symptoms(symptom) VALUES (?)", [(s,) for s in CANONICAL_SYMPTOMS])
    # Sample medicines for testing, covering all 10 canonical symptoms so the
    # teacher-side "narrow down by symptom" suggestion box has something to
    # show for every symptom a student can report.
    conn.executemany("INSERT OR IGNORE INTO medicines(medicine_name,description) VALUES (?,?)", [
      ("พาราเซตามอล", "ลดไข้ แก้ปวด (ตัวอย่างรายการยา)"),
      ("ยาแก้แพ้", "ลดอาการแพ้ ผื่นคัน (ตัวอย่างรายการยา)"),
      ("ยาแก้ไอ", "บรรเทาอาการไอ (ตัวอย่างรายการยา)"),
      ("ยาอมแก้เจ็บคอ", "บรรเทาอาการเจ็บคอ (ตัวอย่างรายการยา)"),
      ("ยาลดกรด/ธาตุน้ำขาว", "บรรเทาอาการปวดท้อง (ตัวอย่างรายการยา)"),
      ("ผงเกลือแร่ (ORS)", "ทดแทนน้ำและเกลือแร่เมื่อท้องเสีย (ตัวอย่างรายการยา)"),
      ("ยาดม", "บรรเทาอาการเวียนหัว (ตัวอย่างรายการยา)"),
      ("เบตาดีนและพลาสเตอร์ปิดแผล", "ทำความสะอาดและปิดแผล (ตัวอย่างรายการยา)")])
    # Sample symptom mapping so the "คลังยา" tab isn't empty on first run.
    conn.executemany("""INSERT OR IGNORE INTO medicine_symptoms(medicine_id,symptom)
      SELECT medicine_id,? FROM medicines WHERE medicine_name=?""", [
      ("ปวดหัว", "พาราเซตามอล"), ("มีไข้", "พาราเซตามอล"), ("ตัวร้อน", "พาราเซตามอล"),
      ("ผื่นคัน", "ยาแก้แพ้"),
      ("ไอ", "ยาแก้ไอ"),
      ("เจ็บคอ", "ยาอมแก้เจ็บคอ"),
      ("ปวดท้อง", "ยาลดกรด/ธาตุน้ำขาว"),
      ("ท้องเสีย", "ผงเกลือแร่ (ORS)"), ("ท้องเสีย", "ยาลดกรด/ธาตุน้ำขาว"),
      ("เวียนหัว", "ยาดม"),
      ("บาดเจ็บ/มีแผล", "เบตาดีนและพลาสเตอร์ปิดแผล")])
    conn.executemany("INSERT OR IGNORE INTO symptom_rules(symptom,preliminary_assessment,priority) VALUES (?,?,?)", [
      ("ปวดหัว", "อาการปวดศีรษะ", 1), ("มีไข้", "อาการไข้", 2), ("ตัวร้อน", "อาการไข้", 2),
      ("เจ็บคอ", "อาการทางเดินหายใจส่วนต้น", 1), ("ไอ", "อาการทางเดินหายใจ", 1),
      ("ปวดท้อง", "อาการทางเดินอาหาร", 1), ("ท้องเสีย", "อาการทางเดินอาหาร", 2),
      ("ผื่นคัน", "อาการผิวหนัง/แพ้", 2), ("บาดเจ็บ/มีแผล", "บาดเจ็บ", 3)])

    conn.commit()
    conn.close()
    print(f"Created / upgraded: {DB_PATH.resolve()}")
    print("Sample student login: 12345 / 2010-05-15")
    print("Next step: start the server (python app.py) then call /api/bootstrap-teacher")
    print("           once to create the first teacher account + shared access code.")

if __name__ == "__main__":
    main()
