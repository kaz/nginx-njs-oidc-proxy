import lib from "js/lib.js";

// `printError` puts error message to user-agent with code=500, and deletes cookie.
var printError = (r, code, msg) => {
	r.headersOut["Content-Type"] = "text/plain";
	lib.cookie.set(r, null);
	r.return(code, msg);
};

// `baseHandler` is higher-order function, which receives `inheritedHandler`(function) and returns new handler which catches errors throwed in `inheritedHandler`.
var baseHandler = inheritedHandler => r => {
	try {
		inheritedHandler(r);
	} catch(e) {
		var reqId = r.variables["request_id"];
		printError(r, 500, `An error occured. Please contact with administrators, and tell them a tracking reference: ${reqId}`);

		r.error(`[baseHandler] Failed: req_id=${reqId}, error=${e}`);
	}
};

// `callbackHandler` is handler, which handles oauth2 callback.
var callbackHandler = baseHandler(r => {
	var context = lib.cookie.get(r);

	// When `expectedState`(read from UA's cookie) and `actualState`(passed from OpenID provider) are not match, this request must be rejected.
	var expectedState = context.state;
	var actualState = decodeURIComponent(r.variables["arg_state"]);
	if (expectedState !== actualState) {
		throw new Error(`unmached state: expected=${expectedState}, actual=${actualState}`);
	}

	// Exchange code with ID token.
	var query = {
		code: decodeURIComponent(r.variables["arg_code"]),
		client_id: lib.oauthClient.getId(),
		client_secret: lib.oauthClient.getSecret(),
		grant_type: "authorization_code",
		redirect_uri: `${r.variables["scheme"]}://${r.variables["host"]}/oauth2/callback`,
	};
	r.subrequest("/oauth2/internal/token", {method: "POST", body: JSON.stringify(query)}, sr => {
		if (sr.status !== 200) {
			throw new Error(`failed to fetch token: status=${sr.status}, resp=${sr.responseBody}`);
		}

		// Parse ID token, which is encoded with JWT.
		var resp = JSON.parse(sr.responseBody);
		var fragments = (resp.id_token || "").split(".");
		if (fragments.length !== 3) {
			throw new Error(`invalid id_token format: id_token=${resp.id_token}`);
		}

		var claims = JSON.parse(String.bytesFrom(fragments[1], "base64url"));
		if (!claims.email || !claims.email_verified) {
			throw new Error(`invalid email: claims=${JSON.stringify(claims)}`);
		}

		// Re-sign email address with our key and store it in cookie.
		lib.cookie.set(r, {email: claims.email});
		r.return(302, context.redirect);
	});
});

// `authHandler` is higher-order function, which receives `ruleFn`(function) that determines permissions,
// and returns a handler which blocks unauthorized users and redirect them to OpenID provider.
var authHandler = ruleFn => baseHandler(r => {
	var claims;

	try {
		claims = lib.cookie.get(r);
		if (!("email" in claims)) {
			throw new Error("not authorized yet");
		}
	} catch(e) {
		// Store `state` into cookie, which will be confirmed on oauth-callback endpoint.
		var reqId = r.variables["request_id"];
		lib.cookie.set(r, {
			state: reqId,
			redirect: r.variables["request_uri"],
		});

		var query = {
			client_id: lib.oauthClient.getId(),
			redirect_uri: `${r.variables["scheme"]}://${r.variables["host"]}/oauth2/callback`,
			response_type: "code",
			scope: "openid email",
			state: reqId,
		};
		r.return(302, `https://accounts.google.com/o/oauth2/v2/auth?${lib.query.stringify(query)}`);

		r.log(`[authHandler] Redirected: error=${e}`);
		return;
	}

	// Check the user can access this application.
	if (!ruleFn(claims.email)) {
		printError(r, 403, `You cannot access this application. Email: ${claims.email}`);
		return;
	}

	// These variables below can read in nginx-configuration.
	r.variables["oidc_email"] = claims.email;
	r.variables["oidc_basic_auth"] = `${claims.email}:`.toUTF8().toString("base64");

	r.internalRedirect("@upstream");
});

export default {
	auth: authHandler,
	callback: callbackHandler,
};
