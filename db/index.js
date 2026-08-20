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
	role TEXT NOT NULL DEFAULT 'auditor' CHECK(role IN ('superadmin','admin','editor','member','auditor')),
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

CREATE TABLE IF NOT EXISTS note_files (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	note_id INTEGER NOT NULL REFERENCES case_notes(id) ON DELETE CASCADE,
	filename TEXT NOT NULL,
	mimetype TEXT,
	data TEXT NOT NULL,
	size INTEGER NOT NULL,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_identities_case ON linked_identities(case_id);
CREATE INDEX IF NOT EXISTS idx_identities_platform ON linked_identities(platform, status);
CREATE INDEX IF NOT EXISTS idx_history_identity ON name_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_files_note ON note_files(note_id);
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

// SQLite can't ALTER a CHECK constraint in place, so rebuild admin_users if its
// role CHECK predates the 'member' role (existing databases only).
async function ensureMemberRole() {
	const row = await get("SELECT sql FROM sqlite_master WHERE type='table' AND name='admin_users'");
	if (!row || row.sql.includes("'member'")) return;

	await run("PRAGMA foreign_keys = OFF");
	// Without this, renaming admin_users rewrites the admin_users FK in every
	// referencing table (cases, case_notes, etc.) to point at the renamed table.
	await run("PRAGMA legacy_alter_table = ON");
	await run("ALTER TABLE admin_users RENAME TO admin_users_old");
	await run(`
		CREATE TABLE admin_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'auditor' CHECK(role IN ('superadmin','admin','editor','member','auditor')),
			created_at TEXT NOT NULL DEFAULT (datetime('now'))
		)
	`);
	await run("INSERT INTO admin_users (id, username, password_hash, totp_secret, role, created_at) SELECT id, username, password_hash, totp_secret, role, created_at FROM admin_users_old");
	await run("DROP TABLE admin_users_old");
	await run("PRAGMA legacy_alter_table = OFF");
	await run("PRAGMA foreign_keys = ON");
}

// Repairs tables left referencing 'admin_users_old' by a prior run of ensureMemberRole
// that executed before PRAGMA legacy_alter_table was applied to that migration.
async function ensureAdminUserFkReferences() {
	const rebuilds = {
		cases: {
			createSql: `CREATE TABLE cases (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				title TEXT NOT NULL,
				created_by INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
				created_at TEXT NOT NULL DEFAULT (datetime('now')),
				updated_at TEXT NOT NULL DEFAULT (datetime('now'))
			)`,
			columns: ["id", "title", "created_by", "created_at", "updated_at"],
		},
		case_notes: {
			createSql: `CREATE TABLE case_notes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
				admin_user_id INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
				body TEXT NOT NULL,
				created_at TEXT NOT NULL DEFAULT (datetime('now'))
			)`,
			columns: ["id", "case_id", "admin_user_id", "body", "created_at"],
		},
		linked_identities: {
			createSql: `CREATE TABLE linked_identities (
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
			)`,
			columns: [
				"id", "case_id", "platform", "platform_user_id", "status",
				"username", "display_name", "last_checked_at", "added_by", "created_at",
			],
		},
		audit_log: {
			createSql: `CREATE TABLE audit_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				admin_user_id INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
				action TEXT NOT NULL,
				detail TEXT,
				created_at TEXT NOT NULL DEFAULT (datetime('now'))
			)`,
			columns: ["id", "admin_user_id", "action", "detail", "created_at"],
		},
	};

	const rows = await all(
		`SELECT name, sql FROM sqlite_master WHERE type='table' AND name IN (${Object.keys(rebuilds)
			.map(() => "?")
			.join(",")})`,
		Object.keys(rebuilds)
	);
	const broken = rows.filter((r) => r.sql && r.sql.includes("admin_users_old"));
	if (broken.length === 0) return;

	await run("PRAGMA foreign_keys = OFF");
	await run("PRAGMA legacy_alter_table = ON");
	for (const { name } of broken) {
		const { createSql, columns } = rebuilds[name];
		const cols = columns.join(", ");
		await run(`ALTER TABLE ${name} RENAME TO ${name}_fkfix_old`);
		await run(createSql);
		await run(`INSERT INTO ${name} (${cols}) SELECT ${cols} FROM ${name}_fkfix_old`);
		await run(`DROP TABLE ${name}_fkfix_old`);
	}
	await run("PRAGMA legacy_alter_table = OFF");
	await run("PRAGMA foreign_keys = ON");
}

// Backfills name_history for identities that have a checked name but no
// history entries at all (e.g. added before initial-name logging existed).
async function ensureInitialNameHistory() {
	const rows = await all(
		`SELECT li.id, li.username, li.display_name
		 FROM linked_identities li
		 WHERE li.last_checked_at IS NOT NULL
		   AND NOT EXISTS (SELECT 1 FROM name_history nh WHERE nh.identity_id = li.id)`
	);
	for (const row of rows) {
		await run(
			"INSERT INTO name_history (identity_id, username, display_name) VALUES (?, ?, ?)",
			[row.id, row.username, row.display_name]
		);
	}
}

async function initSchema() {
	await execSchema();
	await ensureColumn("admin_users", "role", "TEXT NOT NULL DEFAULT 'auditor'");
	await ensureMemberRole();
	await ensureAdminUserFkReferences();
	// Rebuilding tables above drops any indexes that belonged to them; recreate.
	await execSchema();
	await ensureInitialNameHistory();
}

module.exports = { db, run, get, all, initSchema };
