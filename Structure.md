memory-vault/
├── __init__.py
├── vault.py          # Main Vault class (write/recall entrypoints)
├── db.py             # SQLite setup, metadata tables
├── crypto.py         # Encryption profiles, encrypt/decrypt
├── models.py         # Dataclasses for schemas
├── boundary.py       # Integration stub with boundary-daemon
├── utils.py          # Hashing, timestamps, etc.
├── config.py         # Default profiles, paths
└── main.py           # CLI for testing
