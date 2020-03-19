import crypto from "crypto";
import config from "js/config.js";

// `sign` creates signature from `data`(bytes/strings), using `config.cookieSecret` as HMAC key.
var sign = data => crypto.createHmac("sha256", config.cookieSecret).update(data).digest("base64url");

// `createSignedCookie` creates JWT from `data`(object), and returns it.
var createSignedCookie = data => {
	var header = {
		alg: "HS256",
		typ: "JWT",
	};

	var now = Math.floor(new Date().getTime() / 1000);
	var claims = Object.assign({
		nbf: now,
		exp: now + config.cookieLifetime,
	}, data);

	var fragments = [header, claims].map(e => JSON.stringify(e).toUTF8().toString("base64url"));
	fragments.push(sign(fragments.join(".")));

	return fragments.join(".");
};

// `verifySignedCookie` verifies signature in `signedCookie`(JWT string).
// If it is valid, return decoded claims. Otherwise throws error.
var verifySignedCookie = signedCookie => {
	var fragments = signedCookie.split(".");
	if (fragments.length !== 3) {
		throw new Error("invalid cookie format");
	}

	var signature = fragments.pop();
	if (signature !== sign(fragments.join("."))) {
		throw new Error("invalid signature");
	}

	var claims = JSON.parse(String.bytesFrom(fragments.pop(), "base64url"));

	var now = Math.floor(new Date().getTime() / 1000);
	if (now < claims.nbf || claims.exp < now) {
		throw new Error("expired cookie");
	}

	return claims;
};

// `setCookie` sets signed cookie, which is created from `data`(object), to `r`(nginx request obj).
// If `data` is null, removes cookie from user-agent.
var setCookie = (r, data) => {
	var cookie = {
		[config.cookieName]: data ? createSignedCookie(data) : "nil",
		Path: "/",
		SameSite: "Lax",
		HttpOnly: null,
	};
	if (r.variables["https"]) {
		cookie["Secure"] = null;
	}
	if (data) {
		cookie["Max-Age"] = config.cookieLifetime;
	} else {
		cookie["Expires"] = new Date(0).toUTCString();
	}
	r.headersOut["Set-Cookie"] = stringifyCookie(cookie);
};

// `getCookie` reads signed cookie from `r`(nginx request obj), then verifies and returns it.
var getCookie = r => {
	return verifySignedCookie(r.variables[`cookie_${config.cookieName}`] || "");
};

// `stringify` serialize `data`(object) to URI query(w/ delimiter="&") or cookie(w/ delimiter="; ") string.
var stringify = (delimiter, encoder) => data => Object.entries(data).map(kv => kv.map(encoder)).map(kv => kv[1] ? kv.join("=") : kv[0]).join(delimiter);
var stringifyQuery = stringify("&", encodeURIComponent);
var stringifyCookie = stringify("; ", a => a);

export default {
	query: {
		stringify: stringifyQuery,
	},
	cookie: {
		set: setCookie,
		get: getCookie,
	},
	oauthClient: {
		getId: () => config.clientId,
		getSecret: () => config.clientSecret,
	},
};
