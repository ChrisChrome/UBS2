const bcrypt = require("bcrypt");
const { TOTP, NobleCryptoPlugin, ScureBase32Plugin } = require("otplib");

const SALT_ROUNDS = 12;
// otplib v13 requires explicit crypto/base32 plugins per TOTP instance.
const crypto = new NobleCryptoPlugin();
const base32 = new ScureBase32Plugin();

function hashPassword(password) {
	return bcrypt.hash(password, SALT_ROUNDS);
}

function verifyPassword(password, hash) {
	return bcrypt.compare(password, hash);
}

function generateTotpSecret() {
	return new TOTP({ crypto, base32 }).generateSecret();
}

async function verifyTotp(token, secret) {
	if (!token) return false;
	const result = await new TOTP({ crypto, base32, secret }).verify(token);
	return result.valid;
}

function totpKeyUri(username, secret, issuer = "UBS") {
	return new TOTP({ crypto, base32, secret, label: username, issuer }).toURI();
}

module.exports = {
	hashPassword,
	verifyPassword,
	generateTotpSecret,
	verifyTotp,
	totpKeyUri,
};
