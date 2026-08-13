const queries = require("../db/queries");

const SWEEP_INTERVAL_MS = 10 * 60 * 1000;

async function enforceBanForIdentity(discordClient, identity) {
	if (identity.platform !== "discord" || identity.status !== "verified") return;

	for (const guild of discordClient.guilds.cache.values()) {
		try {
			const existingBan = await guild.bans.fetch(identity.platform_user_id).catch(() => null);
			if (existingBan) continue;

			await guild.bans.create(identity.platform_user_id, {
				reason: `UBS: verified alt/alias (case #${identity.case_id})`,
			});
			await queries.logBanAction(identity.id, guild.id, "banned", null);
			console.log(`[BanEnforcer] Banned ${identity.platform_user_id} in guild ${guild.name} (${guild.id})`);
		} catch (err) {
			await queries.logBanAction(identity.id, guild.id, "ban_failed", err.message);
			console.error(
				`[BanEnforcer] Failed to ban ${identity.platform_user_id} in guild ${guild.id}: ${err.message}`
			);
		}
	}
}

async function sweepVerifiedBans(discordClient) {
	const identities = await queries.getVerifiedDiscordIdentities();
	for (const identity of identities) {
		await enforceBanForIdentity(discordClient, identity);
	}
}

function startBanSweep(discordClient, intervalMs = SWEEP_INTERVAL_MS) {
	const timer = setInterval(() => {
		sweepVerifiedBans(discordClient).catch((err) => {
			console.error(`[BanEnforcer] sweep failed: ${err.message}`);
		});
	}, intervalMs);
	timer.unref();
	return timer;
}

// Catches verified alts that join a guild after being added to a case.
function registerGuildMemberHandler(discordClient) {
	discordClient.on("guildMemberAdd", async (member) => {
		try {
			const identity = await queries.getIdentity("discord", member.id);
			if (identity && identity.status === "verified") {
				await enforceBanForIdentity(discordClient, identity);
			}
		} catch (err) {
			console.error(`[BanEnforcer] guildMemberAdd handler failed: ${err.message}`);
		}
	});
}

module.exports = {
	enforceBanForIdentity,
	sweepVerifiedBans,
	startBanSweep,
	registerGuildMemberHandler,
};
