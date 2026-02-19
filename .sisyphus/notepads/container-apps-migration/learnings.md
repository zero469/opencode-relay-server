## 2026-02-19 SQLite + Azure Files Locking Issue

- Container App revision 0000003 crash-looped with: `Failed to connect to database: database is locked (5) (SQLITE_BUSY)`
- Root cause: Azure Files uses SMB protocol which doesn't support POSIX file locking needed by SQLite
- SQLite driver: `modernc.org/sqlite` (pure Go implementation)
- Current DSN: just the path, no pragmas
- Fix needed: Add `_pragma=busy_timeout(10000)&_pragma=journal_mode(DELETE)` to DSN
- DELETE journal mode uses rollback journals instead of WAL, which is more SMB-compatible
- Also need `_txlock=immediate` to avoid SQLITE_BUSY on write transactions

## Azure Container Apps Config
- Revision mode changed to "multiple" to allow traffic splitting during rollbacks
- Volume: `relay-data-volume` (Azure Files `opencoderelayst/relay-data`) mounted at `/data`
- DATABASE_PATH env var = `/data/relay.db`
