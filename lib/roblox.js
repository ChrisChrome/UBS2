const ROBLOX_USER_URL = (id) => `https://users.roblox.com/v1/users/${id}`;

async function fetchRobloxUser(userId) {
	const res = await fetch(ROBLOX_USER_URL(userId));
	if (!res.ok) {
		throw new Error(`Roblox API returned ${res.status} for user ${userId}`);
	}
	const data = await res.json();
	return { username: data.name, displayName: data.displayName };
}

module.exports = { fetchRobloxUser };
