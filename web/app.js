const path = require("path");
const express = require("express");
const session = require("express-session");
const QRCode = require("qrcode");
const multer = require("multer");

const queries = require("../db/queries");
const {
	hashPassword,
	verifyPassword,
	generateTotpSecret,
	verifyTotp,
	totpKeyUri,
} = require("../lib/auth");
const { enforceBanForIdentity } = require("../lib/banEnforcer");
const { checkDiscordIdentity, checkRobloxIdentity } = require("../lib/nameWatcher");
const {
	canEditCases,
	canAddIdentities,
	canManageUsers,
	canDeleteNotes,
	canDeleteCases,
	canViewAuditLog,
	assignableRoles,
	canActOnUserRole,
} = require("../lib/permissions");

const MAX_FILE_SIZE_MB = Number(process.env.MAX_FILE_SIZE_MB) || 10;
const upload = multer({
	storage: multer.memoryStorage(),
	limits: { fileSize: MAX_FILE_SIZE_MB * 1024 * 1024 },
});

function createApp(discordClient) {
	const app = express();

	if (!process.env.SESSION_SECRET) {
		throw new Error("SESSION_SECRET is not set in .env");
	}

	// Only honor X-Forwarded-For when we know we're actually behind a trusted proxy.
	if (String(process.env.TRUST_PROXY).toLowerCase() === "true") {
		app.set("trust proxy", true);
	}

	app.set("view engine", "ejs");
	app.set("views", path.join(__dirname, "views"));
	app.use(express.urlencoded({ extended: false }));
	app.use(
		session({
			secret: process.env.SESSION_SECRET,
			resave: false,
			saveUninitialized: false,
			cookie: { httpOnly: true, sameSite: "lax", maxAge: 1000 * 60 * 60 * 8 },
		})
	);

	function requireAuth(req, res, next) {
		if (req.session.adminId) return next();
		res.redirect("/login");
	}

	function requirePermission(check) {
		return (req, res, next) => {
			if (!req.session.adminId) return res.redirect("/login");
			if (!check(req.session.role)) return res.status(403).send("Forbidden");
			next();
		};
	}

	function triggerBanIfVerifiedDiscord(identity) {
		if (identity && identity.platform === "discord" && identity.status === "verified" && discordClient) {
			enforceBanForIdentity(discordClient, identity).catch((err) =>
				console.error(`[Web] immediate ban enforcement failed: ${err.message}`)
			);
		}
	}

	function auditRaw(adminUserId, action, detail) {
		queries.logAudit(adminUserId, action, detail).catch((err) =>
			console.error(`[Web] audit log write failed: ${err.message}`)
		);
	}

	function audit(req, action, detail) {
		auditRaw(req.session.adminId, action, detail);
	}

	function safeFilename(name) {
		return String(name).replace(/["\r\n]/g, "_");
	}

	// -- First-run setup (only reachable while no admin account exists) --
	app.get("/setup", async (req, res) => {
		const count = await queries.countAdminUsers();
		if (count > 0) return res.redirect("/login");

		if (!req.session.pendingSetup) {
			req.session.pendingSetup = { secret: generateTotpSecret() };
		}
		const keyUri = totpKeyUri("admin", req.session.pendingSetup.secret, "UBS");
		const qr = await QRCode.toDataURL(keyUri);
		res.render("setup", { error: null, secret: req.session.pendingSetup.secret, qr });
	});

	app.post("/setup", async (req, res) => {
		const count = await queries.countAdminUsers();
		if (count > 0) return res.redirect("/login");

		const pending = req.session.pendingSetup;
		if (!pending) return res.redirect("/setup");

		const { username, password, totpToken } = req.body;
		const keyUri = totpKeyUri("admin", pending.secret, "UBS");
		const qr = await QRCode.toDataURL(keyUri);

		if (!username || !password) {
			return res.render("setup", { error: "Username and password are required.", secret: pending.secret, qr });
		}
		if (!(await verifyTotp(totpToken, pending.secret))) {
			return res.render("setup", { error: "Invalid authenticator code.", secret: pending.secret, qr });
		}

		const passwordHash = await hashPassword(password);
		await queries.createAdminUser(username.trim(), passwordHash, pending.secret, "superadmin");
		delete req.session.pendingSetup;
		res.redirect("/login");
	});

	// -- Login --
	app.get("/login", async (req, res) => {
		const count = await queries.countAdminUsers();
		if (count === 0) return res.redirect("/setup");
		res.render("login", { error: null });
	});

	app.post("/login", async (req, res) => {
		const { username, password, totpToken } = req.body;
		const admin = await queries.getAdminByUsername(username);
		if (!admin || !(await verifyPassword(password, admin.password_hash))) {
			auditRaw(admin ? admin.id : null, "user.login_failed", `username=${username} ip=${req.ip}`);
			return res.render("login", { error: "Invalid credentials." });
		}
		if (!(await verifyTotp(totpToken, admin.totp_secret))) {
			auditRaw(admin.id, "user.login_failed", `${admin.username} bad TOTP ip=${req.ip}`);
			return res.render("login", { error: "Invalid authenticator code." });
		}

		req.session.adminId = admin.id;
		req.session.username = admin.username;
		req.session.role = admin.role;
		auditRaw(admin.id, "user.login", `${admin.username} ip=${req.ip}`);
		res.redirect("/");
	});

	app.post("/logout", requireAuth, (req, res) => {
		req.session.destroy(() => res.redirect("/login"));
	});

	app.get("/logout", requireAuth, (req, res) => {
		req.session.destroy(() => res.redirect("/login"));
	})

	// -- Self-service account --
	app.get("/account/password", requireAuth, (req, res) => {
		res.render("account_password", { error: null, success: false });
	});

	app.post("/account/password", requireAuth, async (req, res) => {
		const { currentPassword, newPassword, confirmPassword } = req.body;
		const admin = await queries.getAdminById(req.session.adminId);
		const render = (error) => res.render("account_password", { error, success: false });

		if (!currentPassword || !(await verifyPassword(currentPassword, admin.password_hash))) {
			return render("Current password is incorrect.");
		}
		if (!newPassword || newPassword.length < 8) {
			return render("New password must be at least 8 characters.");
		}
		if (newPassword !== confirmPassword) {
			return render("New passwords do not match.");
		}

		await queries.updateAdminPassword(admin.id, await hashPassword(newPassword));
		audit(req, "user.password_change", `${admin.username} changed their own password`);
		res.render("account_password", { error: null, success: true });
	});

	// -- Public API --
	app.get("/api/roblox/:userId/verified", async (req, res) => {
		let verified = false;
		try {
			const identity = await queries.getIdentity("roblox", req.params.userId.trim());
			verified = Boolean(identity && identity.status === "verified");
		} catch (err) {
			console.error(`[Web] roblox verified-check failed: ${err.message}`);
		}
		res.type("text/plain").status(200).send(String(verified));
	});

	// -- Dashboard / cases --
	app.get("/", requireAuth, async (req, res) => {
		const cases = await queries.listCases();
		res.render("dashboard", {
			cases,
			username: req.session.username,
			role: req.session.role,
			canEditCases: canEditCases(req.session.role),
			canManageUsers: canManageUsers(req.session.role),
			canDeleteCases: canDeleteCases(req.session.role),
			canViewAuditLog: canViewAuditLog(req.session.role),
		});
	});

	app.get("/audit-log", requireAuth, requirePermission(canViewAuditLog), async (req, res) => {
		const entries = await queries.getAuditLog();
		res.render("audit_log", {
			entries,
			username: req.session.username,
			canManageUsers: canManageUsers(req.session.role),
		});
	});

	app.get("/cases/new", requireAuth, requirePermission(canEditCases), (req, res) => {
		res.render("case_new", { error: null });
	});

	app.post("/cases", requireAuth, requirePermission(canEditCases), async (req, res) => {
		const { title } = req.body;
		if (!title || !title.trim()) {
			return res.render("case_new", { error: "Title is required." });
		}
		const caseId = await queries.createCase(title.trim(), req.session.adminId);
		audit(req, "case.create", `Case #${caseId}: ${title.trim()}`);
		res.redirect(`/cases/${caseId}`);
	});

	app.get("/cases/:id", requireAuth, async (req, res) => {
		const caseRow = await queries.getCase(req.params.id);
		if (!caseRow) return res.status(404).send("Case not found");

		const identities = await queries.getIdentitiesForCase(caseRow.id);
		const notes = await queries.getNotes(caseRow.id);
		const histories = {};
		for (const identity of identities) {
			histories[identity.id] = await queries.getNameHistory(identity.id);
		}
		for (const note of notes) {
			note.files = await queries.getFilesForNote(note.id);
		}

		const error = req.session.flashError;
		delete req.session.flashError;

		res.render("case_detail", {
			caseItem: caseRow,
			identities,
			notes,
			histories,
			username: req.session.username,
			canEditCases: canEditCases(req.session.role),
			canAddIdentities: canAddIdentities(req.session.role),
			canManageUsers: canManageUsers(req.session.role),
			canDeleteNotes: canDeleteNotes(req.session.role),
			canDeleteCases: canDeleteCases(req.session.role),
			error,
		});
	});

	app.post("/cases/:id/delete", requireAuth, requirePermission(canDeleteCases), async (req, res) => {
		const caseRow = await queries.getCase(req.params.id);
		await queries.deleteCase(req.params.id);
		if (caseRow) audit(req, "case.delete", `Case #${caseRow.id}: ${caseRow.title}`);
		res.redirect("/");
	});

	app.post("/cases/:id/check-names", requireAuth, requirePermission(canManageUsers), async (req, res) => {
		const identities = await queries.getIdentitiesForCase(req.params.id);
		for (const identity of identities) {
			try {
				if (identity.platform === "discord") {
					await checkDiscordIdentity(discordClient, identity);
				} else {
					await checkRobloxIdentity(identity);
				}
			} catch (err) {
				console.error(`[Web] name check failed for ${identity.platform} ${identity.platform_user_id}: ${err.message}`);
			}
		}
		audit(req, "case.check_names", `Case #${req.params.id}: checked ${identities.length} identities`);
		res.redirect(`/cases/${req.params.id}`);
	});

	app.post(
		"/cases/:id/notes",
		requireAuth,
		requirePermission(canAddIdentities),
		(req, res, next) => {
			upload.array("files")(req, res, (err) => {
				if (err) {
					req.session.flashError =
						err.code === "LIMIT_FILE_SIZE"
							? `File too large. Max size is ${MAX_FILE_SIZE_MB} MB.`
							: "File upload failed.";
					return res.redirect(`/cases/${req.params.id}`);
				}
				next();
			});
		},
		async (req, res) => {
			const { body } = req.body;
			if (body && body.trim()) {
				const noteId = await queries.addNote(req.params.id, req.session.adminId, body.trim());
				for (const file of req.files || []) {
					await queries.addNoteFile(
						noteId,
						safeFilename(file.originalname),
						file.mimetype,
						file.buffer.toString("base64"),
						file.size
					);
				}
				audit(req, "note.create", `Case #${req.params.id}`);
			}
			res.redirect(`/cases/${req.params.id}`);
		}
	);

	app.post("/notes/:id/delete", requireAuth, requirePermission(canDeleteNotes), async (req, res) => {
		const note = await queries.getNote(req.params.id);
		if (!note) return res.status(404).send("Note not found");
		await queries.deleteNote(note.id);
		audit(req, "note.delete", `Case #${note.case_id}, note #${note.id}`);
		res.redirect(`/cases/${note.case_id}`);
	});

	app.get("/files/:id", requireAuth, async (req, res) => {
		const file = await queries.getFileById(req.params.id);
		if (!file) return res.status(404).send("File not found");
		const mimetype = file.mimetype || "application/octet-stream";
		// image/svg+xml can carry <script>, so exclude it from inline preview despite the image/ prefix.
		const isPreviewable =
			(mimetype.startsWith("image/") && mimetype !== "image/svg+xml") ||
			mimetype.startsWith("audio/") ||
			mimetype.startsWith("video/") ||
			mimetype === "text/plain";
		const disposition = isPreviewable ? "inline" : "attachment";

		res.set("Content-Type", mimetype);
		// Untrusted mimetype from the uploader; stop browsers from sniffing it into something dangerous.
		res.set("X-Content-Type-Options", "nosniff");
		res.set("Content-Disposition", `${disposition}; filename="${safeFilename(file.filename)}"`);
		res.send(Buffer.from(file.data, "base64"));
	});

	app.post("/cases/:id/identities", requireAuth, requirePermission(canAddIdentities), async (req, res) => {
		const { platform, platformUserId, status } = req.body;
		if (["discord", "roblox"].includes(platform) && platformUserId && platformUserId.trim()) {
			const trimmedId = platformUserId.trim();
			const existing = await queries.getIdentity(platform, trimmedId);
			if (existing) {
				req.session.flashError = `That ${platform} user ID is already linked to a case.`;
				return res.redirect(`/cases/${req.params.id}`);
			}

			// Members may only add unverified links; other roles honor the submitted status.
			const linkedStatus = canEditCases(req.session.role) && status === "verified" ? "verified" : "suspected";
			try {
				const identityId = await queries.addIdentity(
					req.params.id,
					platform,
					trimmedId,
					linkedStatus,
					req.session.adminId
				);
				const identity = await queries.getIdentityById(identityId);
				audit(req, "identity.link", `Case #${req.params.id}: ${platform} ${trimmedId} (${linkedStatus})`);
				try {
					if (platform === "discord") {
						await checkDiscordIdentity(discordClient, identity);
					} else {
						await checkRobloxIdentity(identity);
					}
				} catch (err) {
					console.error(`[Web] initial name check failed for ${platform} ${trimmedId}: ${err.message}`);
				}
				triggerBanIfVerifiedDiscord(await queries.getIdentityById(identityId));
			} catch (err) {
				req.session.flashError = `That ${platform} user ID is already linked to a case.`;
			}
		}
		res.redirect(`/cases/${req.params.id}`);
	});

	app.post("/identities/:id/verify", requireAuth, requirePermission(canEditCases), async (req, res) => {
		const identity = await queries.getIdentityById(req.params.id);
		if (!identity) return res.status(404).send("Identity not found");
		await queries.setIdentityStatus(identity.id, "verified");
		audit(req, "identity.verify", `${identity.platform} ${identity.platform_user_id} (case #${identity.case_id})`);
		triggerBanIfVerifiedDiscord(await queries.getIdentityById(identity.id));
		res.redirect(`/cases/${identity.case_id}`);
	});

	app.post("/identities/:id/unverify", requireAuth, requirePermission(canEditCases), async (req, res) => {
		const identity = await queries.getIdentityById(req.params.id);
		if (!identity) return res.status(404).send("Identity not found");
		await queries.setIdentityStatus(identity.id, "suspected");
		audit(req, "identity.unverify", `${identity.platform} ${identity.platform_user_id} (case #${identity.case_id})`);
		res.redirect(`/cases/${identity.case_id}`);
	});

	app.post("/identities/:id/delete", requireAuth, requirePermission(canEditCases), async (req, res) => {
		const identity = await queries.getIdentityById(req.params.id);
		if (!identity) return res.status(404).send("Identity not found");
		await queries.removeIdentity(identity.id);
		audit(req, "identity.delete", `${identity.platform} ${identity.platform_user_id} (case #${identity.case_id})`);
		res.redirect(`/cases/${identity.case_id}`);
	});

	// -- User management --
	app.get("/users", requireAuth, requirePermission(canManageUsers), async (req, res) => {
		const users = await queries.listAdminUsers();
		res.render("users_list", {
			users,
			actorRole: req.session.role,
			canActOnUserRole,
			username: req.session.username,
			canViewAuditLog: canViewAuditLog(req.session.role),
		});
	});

	app.get("/users/new", requireAuth, requirePermission(canManageUsers), (req, res) => {
		res.render("user_form", {
			error: null,
			mode: "new",
			user: null,
			roles: assignableRoles(req.session.role),
		});
	});

	app.post("/users", requireAuth, requirePermission(canManageUsers), async (req, res) => {
		const { username, password, role } = req.body;
		const allowedRoles = assignableRoles(req.session.role);
		const render = (error) =>
			res.render("user_form", { error, mode: "new", user: null, roles: allowedRoles });

		if (!username || !username.trim() || !password || !allowedRoles.includes(role)) {
			return render("Username, password, and a valid role are required.");
		}

		try {
			const passwordHash = await hashPassword(password);
			const totpSecret = generateTotpSecret();
			await queries.createAdminUser(username.trim(), passwordHash, totpSecret, role);
			audit(req, "user.create", `${username.trim()} (${role})`);
			const keyUri = totpKeyUri(username.trim(), totpSecret, "UBS");
			const qr = await QRCode.toDataURL(keyUri);
			res.render("user_created", { username: username.trim(), secret: totpSecret, qr });
		} catch (err) {
			render(err.message.includes("UNIQUE") ? "That username is already taken." : "Failed to create user.");
		}
	});

	app.get("/users/:id/edit", requireAuth, requirePermission(canManageUsers), async (req, res) => {
		const user = await queries.getAdminById(req.params.id);
		if (!user || !canActOnUserRole(req.session.role, user.role)) {
			return res.status(403).send("Forbidden");
		}
		res.render("user_form", {
			error: null,
			mode: "edit",
			user,
			roles: assignableRoles(req.session.role),
		});
	});

	app.post("/users/:id", requireAuth, requirePermission(canManageUsers), async (req, res) => {
		const user = await queries.getAdminById(req.params.id);
		if (!user || !canActOnUserRole(req.session.role, user.role)) {
			return res.status(403).send("Forbidden");
		}

		const { username, role, password } = req.body;
		const allowedRoles = assignableRoles(req.session.role);
		const render = (error) =>
			res.render("user_form", { error, mode: "edit", user, roles: allowedRoles });

		if (!username || !username.trim() || !allowedRoles.includes(role)) {
			return render("Username and a valid role are required.");
		}

		try {
			await queries.updateAdminUser(user.id, { username: username.trim(), role });
			audit(req, "user.update", `${user.username} -> username=${username.trim()}, role=${role}`);
			if (password && password.trim()) {
				await queries.updateAdminPassword(user.id, await hashPassword(password));
				audit(req, "user.password_reset", username.trim());
			}
			res.redirect("/users");
		} catch (err) {
			render(err.message.includes("UNIQUE") ? "That username is already taken." : "Failed to update user.");
		}
	});

	app.post("/users/:id/delete", requireAuth, requirePermission(canManageUsers), async (req, res) => {
		const user = await queries.getAdminById(req.params.id);
		if (!user || !canActOnUserRole(req.session.role, user.role)) {
			return res.status(403).send("Forbidden");
		}
		await queries.deleteAdminUser(user.id);
		audit(req, "user.delete", `${user.username} (${user.role})`);
		res.redirect("/users");
	});

	app.post("/users/:id/reset-totp", requireAuth, requirePermission(canManageUsers), async (req, res) => {
		const user = await queries.getAdminById(req.params.id);
		if (!user || !canActOnUserRole(req.session.role, user.role)) {
			return res.status(403).send("Forbidden");
		}
		const totpSecret = generateTotpSecret();
		await queries.updateAdminTotpSecret(user.id, totpSecret);
		audit(req, "user.totp_reset", `${user.username}`);
		const keyUri = totpKeyUri(user.username, totpSecret, "UBS");
		const qr = await QRCode.toDataURL(keyUri);
		res.render("totp_reset", { username: user.username, secret: totpSecret, qr });
	});

	return app;
}

module.exports = { createApp };
