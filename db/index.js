const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "..", "ubs.db");

const db = new sqlite3.Database(DB_PATH, (err) => {
	if (err) {
		console.error(`[DB] Failed to open database: ${err.message}`);
	} else {
		console.log("[DB] Connected to the ubs database.");
	}
});

db.configure("busyTimeout", 5000);

function run(sql, params = []) {
	return new Promise((resolve, reject) => {
		db.run(sql, params, function callback(err) {
			if (err) reject(err);
			else resolve({ lastID: this.lastID, changes: this.changes });
		});
	});
}

function get(sql, params = []) {
	return new Promise((resolve, reject) => {
		db.get(sql, params, (err, row) => {
			if (err) reject(err);
			else resolve(row);
		});
	});
}

function all(sql, params = []) {
	return new Promise((resolve, reject) => {
		db.all(sql, params, (err, rows) => {
			if (err) reject(err);
			else resolve(rows);
		});
	});
}

const SCHEMA = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admin_users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE NOT NULL,
	password_hash TEXT NOT NULL,
	totp_secret TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'auditor' CHECK(role IN ('superadmin','admin','editor','auditor')),
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cases (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	title TEXT NOT NULL,
	created_by INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS case_notes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	admin_user_id INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
	body TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS linked_identities (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
	platform TEXT NOT NULL CHECK(platform IN ('discord','roblox')),
	platform_user_id TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'suspected' CHECK(status IN ('verified','suspected')),
	username TEXT,
	display_name TEXT,
	last_checked_at TEXT,
	added_by INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
	created_at TEXT NOT NULL DEFAULT (datetime('now')),
	UNIQUE(platform, platform_user_id)
);

CREATE TABLE IF NOT EXISTS name_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	identity_id INTEGER NOT NULL REFERENCES linked_identities(id) ON DELETE CASCADE,
	username TEXT,
	display_name TEXT,
	changed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ban_actions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	identity_id INTEGER REFERENCES linked_identities(id) ON DELETE CASCADE,
	guild_id TEXT,
	action TEXT NOT NULL,
	detail TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	admin_user_id INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
	action TEXT NOT NULL,
	detail TEXT,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_identities_case ON linked_identities(case_id);
CREATE INDEX IF NOT EXISTS idx_identities_platform ON linked_identities(platform, status);
CREATE INDEX IF NOT EXISTS idx_history_identity ON name_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
`;

function execSchema() {
	return new Promise((resolve, reject) => {
		db.exec(SCHEMA, (err) => {
			if (err) reject(err);
			else resolve();
		});
	});
}

// Adds a column to a table that already exists from before this column was introduced.
async function ensureColumn(table, column, definition) {
	const columns = await all(`PRAGMA table_info(${table})`);
	if (!columns.some((c) => c.name === column)) {
		await run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
	}
}

async function initSchema() {
	await execSchema();
	await ensureColumn("admin_users", "role", "TEXT NOT NULL DEFAULT 'auditor'");
}

module.exports = { db, run, get, all, initSchema };
