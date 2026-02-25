/**
 * Copyright 2013-present NightWorld.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

const Client = require('./client'),
	error = require('./error'),
	runner = require('./runner'),
	token = require('./token');

module.exports = Grant;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
const fns = [
	extractCredentials,
	checkClient,
	checkGrantTypeAllowed,
	checkGrantType,
	checkScope,
	exposeUser,
	checkMfa,
	generateAccessToken,
	generateExpiresTime,
	saveAccessToken,
	generateRefreshToken,
	generateRefreshExpiresTime,
	saveRefreshToken,
	sendResponse
];

/**
 * Grant
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function Grant(config, options, req, res, next) {
	this.config = config;
	this.options = options || {};
	this.model = config.model;
	this.now = new Date();
	this.req = req;
	this.res = res;

	runner(fns, this, next);
}

/**
 * Basic request validation and extraction of grant_type and client creds
 *
 * @param  {Function} done
 * @this   OAuth
 */
function extractCredentials(done) {
	// Only POST via application/x-www-form-urlencoded is acceptable
	if (this.req.method !== 'POST' || !this.req.is('application/x-www-form-urlencoded')) {
		return done(error('invalid_request', 'Method must be POST with application/x-www-form-urlencoded encoding'));
	}

	// Grant type
	this.grantType = this.req.body && this.req.body.grant_type;
	if (!this.grantType || typeof this.grantType !== 'string' || !this.grantType.match(this.config.regex.grantType)) {
		return done(error('invalid_request', 'Invalid or missing grant_type parameter'));
	}

	// Extract credentials
	// http://tools.ietf.org/html/rfc6749#section-3.2.1
	this.client = Client.credsFromBasic(this.req) || Client.credsFromBody(this.req);
	if (!this.client.clientId || !this.client.clientId.match(this.config.regex.clientId)) {
		return done(error('invalid_client', 'Invalid or missing client_id parameter'));
	} else if (!this.client.clientSecret) {
		return done(error('invalid_client', 'Missing client_secret parameter'));
	}

	done();
}


/**
 * Check extracted client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkClient(done) {
	this.model.getClient(this.client.clientId, this.client.clientSecret, (err, client) => {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (!client) {
			return done(error('invalid_client', 'Client credentials are invalid'));
		}

		this.req.oauth = { client: client };

		// preserve secret, but use everything else from this method
		const secret = this.client.clientSecret;
		this.client = client;
		this.client.clientSecret = secret;

		done();
	});
}

/**
 * Delegate to the relvant grant function based on grant_type
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkGrantType(done) {
	if (this.grantType.match(/^[a-zA-Z][a-zA-Z0-9+.-]+:/) && this.model.extendedGrant) {
		return useExtendedGrant.call(this, done);
	}

	switch (this.grantType) {
		case 'authorization_code':
			return useAuthCodeGrant.call(this, done);
		case 'password':
			return usePasswordGrant.call(this, done);
		case 'refresh_token':
			return useRefreshTokenGrant.call(this, done);
		case 'client_credentials':
			return useClientCredentialsGrant.call(this, done);
		case 'urn:custom:mfa-otp':
			return useMfaOtpGrant.call(this, done);
		case 'urn:custom:recovery-code':
			return useRecoveryCodeGrant.call(this, done);
		case 'urn:custom:demo_account':
			return useDemoAccountGrant.call(this, done);
		default:
			done(error('invalid_request', 'Invalid grant_type parameter or parameter missing'));
	}
}

/**
 * Grant for authorization_code grant type
 *
 * @param  {Function} done
 */
function useAuthCodeGrant(done) {
	const code = this.req.body.code;

	if (!code) {
		return done(error('invalid_request', 'No "code" parameter'));
	}

	this.model.getAuthCode(code, (err, authCode) => {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (!authCode || authCode.clientId !== this.client.clientId) {
			return done(error('invalid_grant', 'Invalid code'));
		} else if (authCode.expires < this.now) {
			return done(error('invalid_grant', 'Code has expired'));
		}

		this.user = authCode.user || { id: authCode.userId };
		this.scope = authCode.scope;

		if (!this.user.id) {
			return done(error('server_error', false, 'No user/userId parameter returned from getauthCode'));
		}

		done();
	});
}

/**
 * Grant for password grant type
 *
 * @param  {Function} done
 */
function usePasswordGrant(done) {
	// User credentials
	const uname = this.req.body.username,
		pword = this.req.body.password;
	if (!uname || !pword) {
		return done(error('invalid_client', 'Missing parameters. "username" and "password" are required'));
	}

	return this.model.checkSSOUser(uname, this.req)
		.then(() => {
			return this.model.getUser(uname, pword, (err, user) => {
				if (err) {
					return done(error('server_error', false, err));
				}
				if (!user) {
					return done(error('invalid_grant', 'User credentials are invalid'));
				}

				this.user = user;
				this.scope = this.req.body.scope;

				done();
			}, this.req);
		}).catch((err) => {
			return done(error('sso_user', err));
		});
}

/**
 * Grant for refresh_token grant type
 *
 * @param  {Function} done
 */
function useRefreshTokenGrant(done) {
	const token = this.req.body.refresh_token;

	if (!token) {
		return done(error('invalid_request', 'No "refresh_token" parameter'));
	}

	this.model.getRefreshToken(token, (err, refreshToken) => {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (!refreshToken || refreshToken.clientId !== this.client.clientId) {
			return done(error('invalid_grant', 'Invalid refresh token'));
		} else if (refreshToken.expires !== null &&
			refreshToken.expires < this.now) {
			return done(error('invalid_grant', 'Refresh token has expired'));
		}

		if (!refreshToken.user && !refreshToken.userId) {
			// TODO How was this expected to work?? The function doesn't take these args as is
			return done(error('server_error', false, 'No user/userId parameter returned from getRefreshToken'));
		}

		// isCustomer will be looked at in model.saveAccessToken to be added to the new token
		this.user = refreshToken.user || { id: refreshToken.userId, isCustomer: refreshToken.isCustomer };
		this.scope = refreshToken.scope;

		if (this.model.revokeRefreshToken) {
			return this.model.revokeRefreshToken(token, (err) => {
				if (err) {
					return done(error('server_error', false, err));
				}
				done();
			});
		}

		done();
	});
}

/**
 * Grant for client_credentials grant type
 *
 * @param  {Function} done
 */
function useClientCredentialsGrant(done) {
	// Client credentials
	const clientId = this.client.clientId,
		clientSecret = this.client.clientSecret;

	if (!clientId || !clientSecret) {
		return done(error('invalid_client', 'Missing parameters. "client_id" and "client_secret" are required'));
	}

	return this.model.getUserFromClient(this.client, (err, user) => {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (!user) {
			return done(error('invalid_grant', 'Client credentials are invalid'));
		}

		this.user = user;
		this.scope = this.req.body.scope || this.client.defaultScope;

		done();
	});
}

/**
 * Grant for extended (http://*) grant type
 *
 * @param  {Function} done
 */
function useExtendedGrant(done) {
	this.model.extendedGrant(this.grantType, this.req, (err, supported, user) => {
		if (err) {
			return done(error(err.error || 'server_error', err.description || err.message, err));
		}

		if (!supported) {
			return done(error('invalid_request', 'Invalid grant_type parameter or parameter missing'));
		} else if (!user || user.id === undefined) {
			return done(error('invalid_request', 'Invalid request.'));
		}

		this.user = user;
		done();
	});
}

/**
 * Grant for urn:custom:mfa-otp (http://*) grant type
 *
 * @param  {Function} done
 */
function useMfaOtpGrant(done) {
	if (!this.req.body || !this.req.body.otp || !this.req.body.mfa_token) {
		return done(error('invalid_request', 'You must provide otp and mfa token.'));
	}

	this.model.performMfaOtp(this.req, (err, user) => {
		if (err) {
			return done(err);
		}

		convertMfaBody(this, user);

		done();
	});
}


/**
 * Grant for urn:custom:recovery-code (http://*) grant type
 *
 * @param  {Function} done
 */
function useRecoveryCodeGrant(done) {
	if (!this.req.body || !this.req.body.recovery_code || !this.req.body.mfa_token) {
		return done(error('invalid_request', 'You must provide recovery code and mfa token.'));
	}

	this.model.performRecoveryCode(this.req, (err, user) => {
		if (err) {
			return done(err);
		}

		convertMfaBody(this, user);

		done();
	});
}

/**
 * Grant for urn:custom:demo_account grant type
 *
 * @param  {Function} done
 */
async function useDemoAccountGrant(done) {
	if (!this.req.body || !this.req.body.email) {
		return done(error('invalid_request', 'You must provide an email address.'));
	}

	if (this.req.body.accepts_terms !== 'true') {
		return done(error('invalid_request', 'You must accept the demo terms of service.'));
	}

	try {
		this.user = await this.model.performDemoAccountGrant(this.req);

		if (this.req.body && this.user.expires_in) {
			this.req.body.expires_in = this.user.expires_in;
		}
		done();
	} catch (err) {
		return done(err);
	}
}

function convertMfaBody(self, user) {
	if (user.scope) {
		self.scope = user.scope;
	}

	if (user.client) {
		self.client = user.client;
	}

	if (self.req.body && user.expires_in) {
		self.req.body.expires_in = user.expires_in;
	}

	if (self.req.body && user.expires_at !== undefined) {
		self.req.body.expires_at = user.expires_at;
	}

	self.user = user;
}

/**
 * Check the grant type is allowed for this client
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkGrantTypeAllowed(done) {
	this.model.grantTypeAllowed(this.client.clientId, this.grantType, (err, allowed) => {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (!allowed) {
			return done(error('invalid_client',
				'The grant type is unauthorised for this client_id'));
		}

		done();
	});
}

/**
 * Validate the scope request
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkScope(done) {
	this.model.validateScope(this.scope, this.client, this.user, (err, scope, invalid) => {
		if (err) {
			return done(error('server_error', false, err));
		}
		if (invalid) {
			return done(error('invalid_scope', invalid));
		}

		this.scope = scope;

		done();
	});
}

/**
 * Expose user
 *
 * @param  {Function} done
 * @this   OAuth
 */
function exposeUser(done) {
	this.req.user = this.user;

	done();
}

/**
 * Generate an access token
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateAccessToken(done) {
	token(this, 'accessToken', (err, token) => {
		this.accessToken = token;
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
function saveAccessToken(done) {
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

	this.model.saveAccessToken(accessToken, this.client, expires, this.user, this.scope, this.grantType, (err) => {
		if (err) {
			return done(error('server_error', false, err));
		}
		done();
	});
}

/**
 * Generate a refresh token
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateRefreshToken(done) {
	if (this.config.grants.indexOf('refresh_token') === -1) {
		return done();
	}
	if (this.grantType === 'urn:custom:demo_account') {
		return done();
	}

	token(this, 'refreshToken', (err, token) => {
		this.refreshToken = token;
		done(err);
	});
}

function generateRefreshExpiresTime(done) {
	this.refreshTokenLifetime = this.config.refreshTokenLifetime;

	if (!this.model.generateRefreshExpiresTime) {
		return done();
	}

	this.model.generateRefreshExpiresTime(this.req, (err, expires) => {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (expires !== undefined) {
			this.refreshTokenLifetime = expires;
		}
		done();
	});
}

/**
 * Save refresh token with model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function saveRefreshToken(done) {
	const refreshToken = this.refreshToken;

	if (!refreshToken) {
		return done();
	}

	// Object idicates a reissue
	if (typeof refreshToken === 'object' && refreshToken.refreshToken) {
		this.refreshToken = refreshToken.refreshToken;
		return done();
	}

	// do not issue a refresh token if non-expiring access token
	if (!this.accessTokenLifetime) {
		this.refreshToken = null;
		return done();
	}

	let expires = null;
	if (this.refreshTokenLifetime) {
		expires = new Date(this.now);
		// refresh extends past access token lifetime
		expires.setSeconds(expires.getSeconds() + this.accessTokenLifetime + this.refreshTokenLifetime);
	}

	this.model.saveRefreshToken(refreshToken, this.client.clientId, expires, this.user, this.scope, (err) => {
		if (err) {
			return done(error('server_error', false, err));
		}
		done();
	});
}

/**
 * Check if MFA is enabled for the user. If MFA is enabled save an mfa token
 * and return an error with the mfa token
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkMfa(done) {
	if (this.user && this.user.mfaEnabled && this.grantType === 'password') {
		this.model.saveMfaToken(this.user, this.req, this.client.clientId, (err, result) => {
			if (err) {
				return done(error('server_error', false, err));
			}
			return done(error('mfa_required', result.mfa_token));
		});
	} else {
		done();
	}
}

/**
 * Sends the resulting token(s) and related information to the client
 *
 * @param  {Function} done
 * @this   OAuth
 */
function sendResponse(done) {
	const response = {
		token_type: 'bearer',
		access_token: this.accessToken
	};

	if (this.accessTokenLifetime !== null) {
		response.expires_in = this.accessTokenLifetime;

		if (this.grantType === 'urn:custom:demo_account') {
			// Console uses this for displaying the demo timer banner
			response.expires_at = new Date(Date.now() + this.accessTokenLifetime * 1000).toISOString();
		}
	}

	if (this.refreshToken) {
		response.refresh_token = this.refreshToken;
	}

	if (this.scope) {
		response.scope = this.scope;
	}

	if (this.options.skipResponse) {
		return done();
	}

	this.res.set({ 'Cache-Control': 'no-store', 'Pragma': 'no-cache' });
	this.res.jsonp(response);

	if (this.config.continueAfterResponse) {
		done();
	}
}
