'use strict';

const error = require('./error'),
	runner = require('./runner'),
	token = require('./token');

module.exports = ImplicitGrant;

const fns = [
	checkParams,
	checkClient,
	checkUserApproved,
	generateAccessToken,
	generateExpiresTime,
	saveAccessToken,
	redirect
];

function ImplicitGrant(config, req, res, next, check) {
	this.config = config;
	this.model = config.model;
	this.now = new Date();
	this.req = req;
	this.res = res;
	this.check = check;

	const self = this;

	runner(fns, this, (err) => {
		if (err) {
			if (res.oauthRedirect) {
				// Custom redirect error handler
				res.redirect(self.client.redirectUri + '?error=' + err.error +
          '&error_description=' + err.error_description + '&code=' + err.code);

				return self.config.continueAfterResponse ? next() : null;
			}
			return next(err);
		}
		next();
	});
}

/**
 * Check Request Params
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkParams (done) {
	const body = this.req.body;
	const query = this.req.query;
	if (!body && !query) {
		return done(error('invalid_request'));
	}

	// Response type
	this.responseType = body.response_type || query.response_type;
	if (this.responseType !== 'token') {
		return done(error('invalid_request',
			'Invalid response_type parameter (must be "token")'));
	}

	// Client
	this.clientId = body.client_id || query.client_id;
	if (!this.clientId) {
		return done(error('invalid_request',
			'Invalid or missing client_id parameter'));
	}

	// Redirect URI
	this.redirectUri = body.redirect_uri || query.redirect_uri;
	if (!this.redirectUri) {
		return done(error('invalid_request',
			'Invalid or missing redirect_uri parameter'));
	}

	done();
}

/**
 * Check client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkClient (done) {
	this.model.getClient(this.clientId, null, (err, client) => {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (!client) {
			return done(error('invalid_client', 'Invalid client credentials'));
		} else if (Array.isArray(client.redirectUri)) {
			if (client.redirectUri.indexOf(this.redirectUri) === -1) {
				return done(error('invalid_request', 'redirect_uri does not match'));
			}
			client.redirectUri = this.redirectUri;
		} else if (client.redirectUri !== this.redirectUri) {
			return done(error('invalid_request', 'redirect_uri does not match'));
		}

		// The request contains valid params so any errors after this point
		// are redirected to the redirect_uri
		this.res.redirectUri = client.redirectUri;
		this.res.oauthRedirect = true;
		this.client = client;

		done();
	});
}

/**
 * Check if user is approved
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkUserApproved (done) {
	this.check(this.req, this.client, (err, allowed, user, scope) => {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (!allowed) {
			return done(error('access_denied',
				'The user denied access to your application'));
		}

		this.user = user;
		this.scope = scope;

		done();
	});
}

/**
 * Generate an access token
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateAccessToken (done) {
	token(this, 'accessToken', (err, atoken) => {
		this.accessToken = atoken;
		done(err);
	});
}

function generateExpiresTime(done) {
	this.accessTokenLifetime = this.config.accessTokenLifetime;

	if (!this.model.generateExpiresTime) {
		return done();
	}

	this.model.generateExpiresTime(this.req, (err, expires) => {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (expires !== undefined) {
			this.accessTokenLifetime = expires;
		}
		done();
	});
}

/**
 * Save access token with model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function saveAccessToken (done) {
	const accessToken = this.accessToken;

	// Object indicates a reissue
	if (typeof accessToken === 'object' && accessToken.accessToken) {
		this.accessToken = accessToken.accessToken;
		return done();
	}

	let expires = null;
	if ((this.accessTokenLifetime !== null) && (this.accessTokenLifetime > 0)) {
		expires = new Date(this.now);
		expires.setSeconds(expires.getSeconds() + this.accessTokenLifetime);
	}

	this.model.saveAccessToken(accessToken, this.client, expires,
		this.user, this.scope, this.grantType, (err) => {
			if (err) {
				return done(error('server_error', false, err));
			}
			done();
		});
}

/**
 * Check client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function redirect (done) {
	this.res.redirect(this.client.redirectUri + '#token=' + this.accessToken +
      (this.req.query.state ? '&state=' + this.req.query.state : ''));

	if (this.config.continueAfterResponse) {
		return done();
	}
}
