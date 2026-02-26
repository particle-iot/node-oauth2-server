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

const error = require('./error'),
	runner = require('./runner'),
	token = require('./token');

module.exports = AuthCodeGrant;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
const fns = [
	checkParams,
	checkClient,
	checkUserApproved,
	generateCode,
	saveAuthCode,
	redirect
];

/**
 * AuthCodeGrant
 *
 * @param {Object}   config Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Function} next
 */
function AuthCodeGrant(config, req, res, next, check) {
	this.config = config;
	this.model = config.model;
	this.req = req;
	this.res = res;
	this.check = check;

	runner(fns, this, (err) => {
		if (err && res.oauthRedirect) {
			// Custom redirect error handler
			res.redirect(this.client.redirectUri + '?error=' + err.error +
        '&error_description=' + err.error_description + '&code=' + err.code);

			return this.config.continueAfterResponse ? next() : null;
		}

		next(err);
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
	if (this.responseType !== 'code') {
		return done(error('invalid_request',
			'Invalid response_type parameter (must be "code")'));
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
		this.res.oauthRedirect = true;
		this.client = client;

		done();
	});
}

/**
 * Check client against model
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
 * Check client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateCode (done) {
	token(this, 'authorization_code', (err, code) => {
		this.authCode = code;
		done(err);
	});
}

/**
 * Check client against model
 *
 * @param  {Function} done
 * @this   OAuth
 */
function saveAuthCode (done) {
	const expires = new Date();
	expires.setSeconds(expires.getSeconds() + this.config.authCodeLifetime);

	this.model.saveAuthCode(this.authCode, this.client.clientId, expires, this.user, this.scope, (err) => {
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
	this.res.redirect(this.client.redirectUri + '?code=' + this.authCode +
      (this.req.query.state ? '&state=' + this.req.query.state : ''));

	if (this.config.continueAfterResponse) {
		return done();
	}
}
