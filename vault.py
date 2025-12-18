import sqlite3
import json
import getpass
from .models import MemoryObject, RecallRequest
from .crypto import derive_key_from_passphrase, encrypt_memory, decrypt_memory
from .db import DB_PATH, init_db

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

        # Classification gate (expand with boundary check later)
        classification = row[3]
        if classification >= 3:
            print(f"Level {classification} requires human approval and offline check.")
            # TODO: boundary check + human UX
            approve = input("Approve recall? (yes/no): ")
            if approve.lower() != "yes":
                raise PermissionError("Recall denied")

        # Decrypt in-memory
        ciphertext = row[6]
        plaintext = decrypt_memory(self.key, ciphertext)
        # Log recall
        c.execute('INSERT INTO recall_log VALUES (?, ?, ?, ?, ?, ?)',
                  (str(uuid.uuid4()), memory_id, requester, datetime.utcnow().isoformat(), 1, justification))
        conn.commit()
        conn.close()
        return plaintext
