const { fetchRobloxUser } = require("./roblox");
const queries = require("../db/queries");

const DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

function startNameWatcher(discordClient, intervalMs) {
	const interval = intervalMs || Number(process.env.NAME_CHECK_INTERVAL_MS) || DEFAULT_INTERVAL_MS;
	const timer = setInterval(() => {
		checkAllIdentities(discordClient).catch((err) => {
			console.error(`[NameWatcher] sweep failed: ${err.message}`);
		});
	}, interval);
	timer.unref();
	return timer;
}

async function checkAllIdentities(discordClient) {
	const identities = await queries.getAllIdentities();
	for (const identity of identities) {
		try {
			if (identity.platform === "discord") {
				await checkDiscordIdentity(discordClient, identity);
			} else if (identity.platform === "roblox") {
				await checkRobloxIdentity(identity);
			}
		} catch (err) {
			console.error(
				`[NameWatcher] failed to check ${identity.platform} ${identity.platform_user_id}: ${err.message}`
			);
		}
	}
}

async function checkDiscordIdentity(discordClient, identity) {
	const user = await discordClient.users.fetch(identity.platform_user_id, { force: true });
	await recordIfChanged(identity, user.username, user.globalName || user.username);
}

async function checkRobloxIdentity(identity) {
	const { username, displayName } = await fetchRobloxUser(identity.platform_user_id);
	await recordIfChanged(identity, username, displayName);
}

async function recordIfChanged(identity, username, displayName) {
	const isFirstCheck = identity.last_checked_at === null;
	const changed = username !== identity.username || displayName !== identity.display_name;
	if (isFirstCheck) {
		// Record the initial name so the history isn't missing the identity's starting point.
		await queries.addNameHistory(identity.id, username, displayName);
		console.log(
			`[NameWatcher] ${identity.platform} ${identity.platform_user_id} initial name: ${username}/${displayName}`
		);
	} else if (changed) {
		await queries.addNameHistory(identity.id, username, displayName);
		console.log(
			`[NameWatcher] ${identity.platform} ${identity.platform_user_id} name change: ` +
				`${identity.username}/${identity.display_name} -> ${username}/${displayName}`
		);
	}
	await queries.updateIdentityLastChecked(identity.id, username, displayName);
}

module.exports = { startNameWatcher, checkAllIdentities, checkDiscordIdentity, checkRobloxIdentity };
