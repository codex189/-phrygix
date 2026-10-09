import os, sqlite3, secrets, hashlib, time, threading, email
from datetime import datetime, timezone
from email import policy
from email.utils import parseaddr
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from aiosmtpd.controller import Controller

DOMAIN = os.getenv('MAIL_DOMAIN', 'mail.example.com').lower()
DB = os.getenv('DB_PATH', 'phrygix.sqlite3')
TTL = int(os.getenv('MAILBOX_TTL_SECONDS', '86400'))
MAX_BYTES = int(os.getenv('MAX_MESSAGE_BYTES', '1048576'))
SMTP_HOST = os.getenv('SMTP_HOST', '127.0.0.1')
SMTP_PORT = int(os.getenv('SMTP_PORT', '2525'))
ORIGINS = [s.strip() for s in os.getenv('ALLOWED_ORIGINS', 'http://localhost:8000,http://127.0.0.1:8000').split(',')]
app = FastAPI(title='Phrygix API')
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=['GET','POST','DELETE'], allow_headers=['Authorization','Content-Type'])

@contextmanager
def db():
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.execute('PRAGMA journal_mode=WAL')
        c.execute('CREATE TABLE IF NOT EXISTS boxes (address TEXT PRIMARY KEY, token_hash TEXT NOT NULL, expires INTEGER NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, address TEXT NOT NULL, sender TEXT, subject TEXT, text_body TEXT, received INTEGER NOT NULL, FOREIGN KEY(address) REFERENCES boxes(address))')
        c.execute('CREATE INDEX IF NOT EXISTS idx_messages_address ON messages(address)')

def purge():
    now = int(time.time())
    with db() as c:
        c.execute('DELETE FROM messages WHERE address IN (SELECT address FROM boxes WHERE expires <= ?)', (now,))
        c.execute('DELETE FROM boxes WHERE expires <= ?', (now,))

def auth(address, authorization):
    token = (authorization or '').removeprefix('Bearer ').strip()
    if not token: raise HTTPException(401, 'Missing mailbox token')
    with db() as c:
        row = c.execute('SELECT token_hash, expires FROM boxes WHERE address=?', (address,)).fetchone()
    if not row or row['expires'] <= time.time() or not secrets.compare_digest(row['token_hash'], hashlib.sha256(token.encode()).hexdigest()):
        raise HTTPException(401, 'Invalid or expired mailbox')

@app.on_event('startup')
def start():
    init_db()
    purge()
    if os.getenv('RUN_SMTP', '1') == '1':
        app.state.smtp = Controller(MailHandler(), hostname=SMTP_HOST, port=SMTP_PORT, ready_timeout=10)
        app.state.smtp.start()

@app.on_event('shutdown')
def stop():
    if hasattr(app.state, 'smtp'): app.state.smtp.stop()

@app.post('/api/mailboxes', status_code=201)
def create_box():
    purge()
    token = secrets.token_urlsafe(32)
    expiry = int(time.time()) + TTL
    with db() as c:
        for _ in range(5):
            address = secrets.token_hex(8) + '@' + DOMAIN
            try:
                c.execute('INSERT INTO boxes VALUES (?,?,?)', (address, hashlib.sha256(token.encode()).hexdigest(), expiry))
                break
            except sqlite3.IntegrityError: continue
        else: raise HTTPException(503, 'Could not allocate mailbox')
    return {'email': address, 'token': token, 'expiresAt': datetime.fromtimestamp(expiry, timezone.utc).isoformat()}

@app.get('/api/mailboxes/{address}/messages')
def messages(address: str, authorization: str | None = Header(default=None)):
    auth(address, authorization)
    with db() as c:
        rows = c.execute('SELECT id,sender,subject,received FROM messages WHERE address=? ORDER BY id DESC LIMIT 100', (address,)).fetchall()
    return [{'id':r['id'], 'from':r['sender'], 'subject':r['subject'], 'date':datetime.fromtimestamp(r['received'],timezone.utc).isoformat()} for r in rows]

@app.get('/api/mailboxes/{address}/messages/{id}')
def message(address: str, id: int, authorization: str | None = Header(default=None)):
    auth(address, authorization)
    with db() as c:
        r = c.execute('SELECT * FROM messages WHERE address=? AND id=?', (address,id)).fetchone()
    if not r: raise HTTPException(404, 'Message not found')
    return {'id':r['id'], 'from':r['sender'], 'subject':r['subject'], 'date':datetime.fromtimestamp(r['received'],timezone.utc).isoformat(), 'textBody':r['text_body'], 'htmlBody':''}

@app.delete('/api/mailboxes/{address}', status_code=204)
def delete_box(address: str, authorization: str | None = Header(default=None)):
    auth(address, authorization)
    with db() as c:
        c.execute('DELETE FROM messages WHERE address=?', (address,))
        c.execute('DELETE FROM boxes WHERE address=?', (address,))

@app.get('/api/health')
def health(): return {'status':'ok'}

class MailHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        target = address.lower()
        if not target.endswith('@' + DOMAIN): return '550 Unknown domain'
        with db() as c:
            exists = c.execute('SELECT 1 FROM boxes WHERE address=? AND expires>?', (target,int(time.time()))).fetchone()
        if not exists: return '550 Unknown or expired mailbox'
        envelope.rcpt_tos.append(target)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        raw = envelope.original_content if hasattr(envelope,'original_content') else envelope.content
        if len(raw) > MAX_BYTES: return '552 Message too large'
        try:
            parsed = email.message_from_bytes(raw, policy=policy.default)
            subject = str(parsed.get('subject', ''))[:500]
            sender = parseaddr(str(parsed.get('from','')))[1][:320] or str(envelope.mail_from)[:320]
            body = parsed.get_body(preferencelist=('plain',)) if parsed.is_multipart() else parsed
            text = body.get_content() if body and body.get_content_maintype() == 'text' else ''
            if not isinstance(text, str): text = ''
            now = int(time.time())
            with db() as c:
                for recipient in set(envelope.rcpt_tos):
                    exists = c.execute('SELECT 1 FROM boxes WHERE address=? AND expires>?', (recipient,now)).fetchone()
                    if exists:
                        c.execute('INSERT INTO messages (address,sender,subject,text_body,received) VALUES (?,?,?,?,?)', (recipient,sender,subject,text[:200000],now))
            return '250 Message accepted'
        except Exception:
            return '451 Temporary processing failure'
