import sqlite3
import json
import getpass
from datetime import datetime, timedelta
from .models import MemoryObject, RecallRequest
from .crypto import derive_key_from_passphrase, encrypt_memory, decrypt_memory
from .db import DB_PATH, init_db
from .boundary import check_recall
import uuid

class MemoryVault:
    def __init__(self, passphrase: str = None):
        init_db()
        self.passphrase = passphrase or getpass.getpass("Vault passphrase: ")
        self.key, self.salt = derive_key_from_passphrase(self.passphrase)

    def store_memory(self, obj: MemoryObject):
        if obj.classification < 0 or obj.classification > 5:
            raise ValueError("Invalid classification")
        # Encrypt
        ciphertext, nonce, _ = encrypt_memory(self.key, obj.content_plaintext)
        obj.content_hash = hashlib.sha256(obj.content_plaintext).hexdigest()

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO memories VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            obj.memory_id,
            obj.created_at.isoformat(),
            obj.created_by,
            obj.classification,
            obj.encryption_profile,
            obj.content_hash,
            ciphertext,
            nonce,
            self.salt,
            obj.intent_ref,
            json.dumps(obj.value_metadata),
            json.dumps(obj.access_policy),
            obj.audit_proof
        ))
        conn.commit()
        conn.close()
        print(f"Stored memory {obj.memory_id} at level {obj.classification}")

    def recall_memory(self, memory_id: str, justification: str = "", requester: str = "agent") -> bytes:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM memories WHERE memory_id = ?', (memory_id,))
        row = c.fetchone()
        if not row:
            raise ValueError("Memory not found")

        classification = row[3]
        access_policy = json.loads(row[11])  # access_policy JSON

        # Boundary check via daemon
        permitted, reason = check_recall(classification)
        if not permitted:
            # Log attempted recall as denied
            c.execute('INSERT INTO recall_log VALUES (?, ?, ?, ?, ?, ?)',
                      (str(uuid.uuid4()), memory_id, requester, datetime.utcnow().isoformat(), 0, justification + f" (denied: {reason})"))
            conn.commit()
            conn.close()
            raise PermissionError(f"Boundary check failed: {reason}")

        # Classification gate (local policy, e.g., human approval for high levels)
        if classification >= 3:
            print(f"Level {classification} requires human approval and offline check (already validated by boundary).")
            approve = input("Approve recall? (yes/no): ")
            if approve.lower() != "yes":
                # Log denied
                c.execute('INSERT INTO recall_log VALUES (?, ?, ?, ?, ?, ?)',
                          (str(uuid.uuid4()), memory_id, requester, datetime.utcnow().isoformat(), 0, justification + " (human denied)"))
                conn.commit()
                conn.close()
                raise PermissionError("Recall denied by human")

        # Cooldown enforcement
        cooldown_seconds = access_policy.get("cooldown_seconds", 0)
        if cooldown_seconds > 0:
            c.execute('''
                SELECT timestamp FROM recall_log 
                WHERE memory_id = ? AND approved = 1 
                ORDER BY timestamp DESC LIMIT 1
            ''', (memory_id,))
            last_recall_row = c.fetchone()
            if last_recall_row:
                last_recall_time = datetime.fromisoformat(last_recall_row[0])
                if datetime.utcnow() - last_recall_time < timedelta(seconds=cooldown_seconds):
                    # Log denied due to cooldown
                    c.execute('INSERT INTO recall_log VALUES (?, ?, ?, ?, ?, ?)',
                              (str(uuid.uuid4()), memory_id, requester, datetime.utcnow().isoformat(), 0, justification + " (cooldown active)"))
                    conn.commit()
                    conn.close()
                    raise PermissionError(f"Recall denied: Cooldown active (wait {cooldown_seconds} seconds)")

        # Decrypt in-memory
        ciphertext = row[6]
        plaintext = decrypt_memory(self.key, ciphertext)
        # Log successful recall
        c.execute('INSERT INTO recall_log VALUES (?, ?, ?, ?, ?, ?)',
                  (str(uuid.uuid4()), memory_id, requester, datetime.utcnow().isoformat(), 1, justification))
        conn.commit()
        conn.close()
        return plaintext
