const ROLES = ["superadmin", "admin", "editor", "member", "auditor"];

// superadmin: everything. editor: full case/identity control, no user admin.
// admin: user management only. member: can only add unverified identities. auditor: read-only.
function canEditCases(role) {
	return role === "superadmin" || role === "admin" || role === "editor";
} 

function canAddIdentities(role) {
	return role === "superadmin" || role === "admin" || role === "editor" || role === "member";
}

function canManageUsers(role) {
	return role === "superadmin" || role === "admin";
}

function canDeleteNotes(role) {
	return role === "superadmin" || role === "admin";
}

function canDeleteCases(role) {
	return role === "superadmin";
}

function canViewAuditLog(role) {
	return role === "superadmin" || role === "admin";
}

// Roles an actor is allowed to assign when creating a new user.
function assignableRoles(actorRole) {
	if (actorRole === "superadmin") return ["admin", "editor", "member", "auditor"];
	if (actorRole === "admin") return ["editor", "member", "auditor"];
	return [];
}

// Nobody manages the superadmin; admins are limited to editor/member/auditor targets.
function canActOnUserRole(actorRole, targetRole) {
	if (targetRole === "superadmin") return false;
	if (actorRole === "superadmin") return true;
	if (actorRole === "admin") return targetRole === "editor" || targetRole === "member" || targetRole === "auditor";
	return false;
}

module.exports = {
	ROLES,
	canEditCases,
	canAddIdentities,
	canManageUsers,
	canDeleteNotes,
	canDeleteCases,
	canViewAuditLog,
	assignableRoles,
	canActOnUserRole,
};
