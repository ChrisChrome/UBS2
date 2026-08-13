const { run, get, all } = require("./index");

// -- Admin users --

function countAdminUsers() {
	return get("SELECT COUNT(*) AS count FROM admin_users").then((row) => row.count);
}

function createAdminUser(username, passwordHash, totpSecret, role) {
	return run(
		"INSERT INTO admin_users (username, password_hash, totp_secret, role) VALUES (?, ?, ?, ?)",
		[username, passwordHash, totpSecret, role]
	).then((res) => res.lastID);
}

function getAdminByUsername(username) {
	return get("SELECT * FROM admin_users WHERE username = ?", [username]);
}

function getAdminById(id) {
	return get("SELECT * FROM admin_users WHERE id = ?", [id]);
}

function listAdminUsers() {
	return all("SELECT id, username, role, created_at FROM admin_users ORDER BY created_at ASC");
}

function updateAdminUser(id, { username, role }) {
	return run("UPDATE admin_users SET username = ?, role = ? WHERE id = ?", [username, role, id]);
}

function updateAdminPassword(id, passwordHash) {
	return run("UPDATE admin_users SET password_hash = ? WHERE id = ?", [passwordHash, id]);
}

function updateAdminTotpSecret(id, totpSecret) {
	return run("UPDATE admin_users SET totp_secret = ? WHERE id = ?", [totpSecret, id]);
}

function deleteAdminUser(id) {
	return run("DELETE FROM admin_users WHERE id = ?", [id]);
}

// -- Cases --

function createCase(title, createdBy) {
	return run("INSERT INTO cases (title, created_by) VALUES (?, ?)", [title, createdBy]).then(
		(res) => res.lastID
	);
}

function listCases() {
	return all(
		`SELECT c.*,
			(SELECT COUNT(*) FROM linked_identities li WHERE li.case_id = c.id) AS identity_count
		 FROM cases c ORDER BY c.updated_at DESC`
	);
}

function getCase(id) {
	return get("SELECT * FROM cases WHERE id = ?", [id]);
}

function touchCase(id) {
	return run("UPDATE cases SET updated_at = datetime('now') WHERE id = ?", [id]);
}

function deleteCase(id) {
	return run("DELETE FROM cases WHERE id = ?", [id]);
}

// -- Case notes --

function addNote(caseId, adminUserId, body) {
	return run("INSERT INTO case_notes (case_id, admin_user_id, body) VALUES (?, ?, ?)", [
		caseId,
		adminUserId,
		body,
	]).then((res) => touchCase(caseId).then(() => res.lastID));
}

function getNotes(caseId) {
	return all(
		`SELECT n.*, a.username AS author
		 FROM case_notes n LEFT JOIN admin_users a ON a.id = n.admin_user_id
		 WHERE n.case_id = ? ORDER BY n.created_at DESC`,
		[caseId]
	);
}

function deleteNote(id) {
	return run("DELETE FROM case_notes WHERE id = ?", [id]);
}

function getNote(id) {
	return get("SELECT * FROM case_notes WHERE id = ?", [id]);
}

// -- Note files --

function addNoteFile(noteId, filename, mimetype, dataBase64, size) {
	return run(
		"INSERT INTO note_files (note_id, filename, mimetype, data, size) VALUES (?, ?, ?, ?, ?)",
		[noteId, filename, mimetype, dataBase64, size]
	).then((res) => res.lastID);
}

function getFilesForNote(noteId) {
	return all(
		"SELECT id, note_id, filename, mimetype, size, created_at FROM note_files WHERE note_id = ? ORDER BY created_at ASC",
		[noteId]
	);
}

function getFileById(id) {
	return get("SELECT * FROM note_files WHERE id = ?", [id]);
}

// -- Linked identities --

function addIdentity(caseId, platform, platformUserId, status, addedBy) {
	return run(
		`INSERT INTO linked_identities (case_id, platform, platform_user_id, status, added_by)
		 VALUES (?, ?, ?, ?, ?)`,
		[caseId, platform, platformUserId, status, addedBy]
	).then((res) => touchCase(caseId).then(() => res.lastID));
}

function getIdentitiesForCase(caseId) {
	return all("SELECT * FROM linked_identities WHERE case_id = ? ORDER BY created_at ASC", [
		caseId,
	]);
}

function getIdentity(platform, platformUserId) {
	return get("SELECT * FROM linked_identities WHERE platform = ? AND platform_user_id = ?", [
		platform,
		platformUserId,
	]);
}

function getIdentityById(id) {
	return get("SELECT * FROM linked_identities WHERE id = ?", [id]);
}

function getAllIdentities() {
	return all("SELECT * FROM linked_identities");
}

function getVerifiedDiscordIdentities() {
	return all("SELECT * FROM linked_identities WHERE platform = 'discord' AND status = 'verified'");
}

function setIdentityStatus(id, status) {
	return run("UPDATE linked_identities SET status = ? WHERE id = ?", [status, id]);
}

function removeIdentity(id) {
	return run("DELETE FROM linked_identities WHERE id = ?", [id]);
}

function updateIdentityLastChecked(id, username, displayName) {
	return run(
		`UPDATE linked_identities
		 SET username = ?, display_name = ?, last_checked_at = datetime('now')
		 WHERE id = ?`,
		[username, displayName, id]
	);
}

// -- Name history --

function addNameHistory(identityId, username, displayName) {
	return run(
		"INSERT INTO name_history (identity_id, username, display_name) VALUES (?, ?, ?)",
		[identityId, username, displayName]
	);
}

function getNameHistory(identityId) {
	return all("SELECT * FROM name_history WHERE identity_id = ? ORDER BY changed_at DESC", [
		identityId,
	]);
}

// -- Ban actions --

function logBanAction(identityId, guildId, action, detail) {
	return run(
		"INSERT INTO ban_actions (identity_id, guild_id, action, detail) VALUES (?, ?, ?, ?)",
		[identityId, guildId, action, detail]
	);
}

// -- Audit log --

function logAudit(adminUserId, action, detail) {
	return run("INSERT INTO audit_log (admin_user_id, action, detail) VALUES (?, ?, ?)", [
		adminUserId,
		action,
		detail || null,
	]);
}

function getAuditLog(limit = 200) {
	return all(
		`SELECT a.*, u.username AS actor
		 FROM audit_log a LEFT JOIN admin_users u ON u.id = a.admin_user_id
		 ORDER BY a.created_at DESC, a.id DESC
		 LIMIT ?`,
		[limit]
	);
}

module.exports = {
	countAdminUsers,
	createAdminUser,
	getAdminByUsername,
	getAdminById,
	listAdminUsers,
	updateAdminUser,
	updateAdminPassword,
	updateAdminTotpSecret,
	deleteAdminUser,
	createCase,
	listCases,
	getCase,
	touchCase,
	deleteCase,
	addNote,
	getNotes,
	deleteNote,
	getNote,
	addNoteFile,
	getFilesForNote,
	getFileById,
	addIdentity,
	getIdentitiesForCase,
	getIdentity,
	getIdentityById,
	getAllIdentities,
	getVerifiedDiscordIdentities,
	setIdentityStatus,
	removeIdentity,
	updateIdentityLastChecked,
	addNameHistory,
	getNameHistory,
	logBanAction,
	logAudit,
	getAuditLog,
};
