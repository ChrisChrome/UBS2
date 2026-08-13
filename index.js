require("dotenv").config({quiet:true});
const Discord = require("discord.js");
const { initSchema } = require("./db");
const { createApp } = require("./web/app");
const { startNameWatcher } = require("./lib/nameWatcher");
const { startBanSweep, registerGuildMemberHandler, sweepVerifiedBans } = require("./lib/banEnforcer");

const client = new Discord.Client({
	intents: [
		"Guilds",
		"GuildBans",
		"GuildMembers"
	]
});

client.once("clientReady", async () => {
	console.log(`[Discord] Logged in as ${client.user.username} (${client.user.id})`);
	registerGuildMemberHandler(client);
	startNameWatcher(client);
	startBanSweep(client);
	sweepVerifiedBans(client).catch((err) => console.error(`[BanEnforcer] initial sweep failed: ${err.message}`));
});

async function main() {
	await initSchema();

	client.login(process.env.DISCORD_TOKEN).catch((err) => {
		console.log(`[Discord] Failed to login: ${err}`);
	});

	const app = createApp(client);
	const port = process.env.WEB_PORT || 3000;
	app.listen(port, () => {
		console.log(`[Web] Admin interface listening on http://localhost:${port}`);
	});
}

main().catch((err) => {
	console.error(`[Startup] Fatal error: ${err.message}`);
	process.exit(1);
});