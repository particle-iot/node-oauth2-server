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

var Client = require('./client'),
  error = require('./error'),
  runner = require('./runner'),
  token = require('./token');

module.exports = Grant;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
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
function Grant (config, options, req, res, next) {
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
function extractCredentials (done) {
  // Only POST via application/x-www-form-urlencoded is acceptable
  if (this.req.method !== 'POST' ||
      !this.req.is('application/x-www-form-urlencoded')) {
    return done(error('invalid_request',
      'Method must be POST with application/x-www-form-urlencoded encoding'));
  }

  // Grant type
  this.grantType = this.req.body && this.req.body.grant_type;
  if (!this.grantType || !this.grantType.match(this.config.regex.grantType)) {
    return done(error('invalid_request',
      'Invalid or missing grant_type parameter'));
  }

  // Extract credentials
  // http://tools.ietf.org/html/rfc6749#section-3.2.1
  this.client = Client.credsFromBasic(this.req) || Client.credsFromBody(this.req);
  if (!this.client.clientId ||
      !this.client.clientId.match(this.config.regex.clientId)) {
    return done(error('invalid_client',
      'Invalid or missing client_id parameter'));
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
function checkClient (done) {
  var self = this;

  this.model.getClient(this.client.clientId, this.client.clientSecret,
      function (err, client) {
    if (err) return done(error('server_error', false, err));

    if (!client) {
      return done(error('invalid_client', 'Client credentials are invalid'));
    }

    self.req.oauth = { client: client };

    // preserve secret, but use everything else from this method
    var secret = self.client.clientSecret;
    self.client = client;
    self.client.clientSecret = secret;

    done();
  });
}

/**
 * Delegate to the relvant grant function based on grant_type
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkGrantType (done) {
  if (this.grantType.match(/^[a-zA-Z][a-zA-Z0-9+.-]+:/)
      && this.model.extendedGrant) {
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
    default:
      done(error('invalid_request',
        'Invalid grant_type parameter or parameter missing'));
  }
}

/**
 * Grant for authorization_code grant type
 *
 * @param  {Function} done
 */
function useAuthCodeGrant (done) {
  var code = this.req.body.code;

  if (!code) {
    return done(error('invalid_request', 'No "code" parameter'));
  }

  var self = this;
  this.model.getAuthCode(code, function (err, authCode) {
    if (err) return done(error('server_error', false, err));

    if (!authCode || authCode.clientId !== self.client.clientId) {
      return done(error('invalid_grant', 'Invalid code'));
    } else if (authCode.expires < self.now) {
      return done(error('invalid_grant', 'Code has expired'));
    }

    self.user = authCode.user || { id: authCode.userId };
    self.scope = authCode.scope;

    if (!self.user.id) {
      return done(error('server_error', false,
        'No user/userId parameter returned from getauthCode'));
    }

    done();
  });
}

/**
 * Grant for password grant type
 *
 * @param  {Function} done
 */
function usePasswordGrant (done) {
  // User credentials
  var uname = this.req.body.username,
    pword = this.req.body.password;
  if (!uname || !pword) {
    return done(error('invalid_client',
      'Missing parameters. "username" and "password" are required'));
  }

  var self = this;
  return this.model.getUser(uname, pword, function (err, user) {
    if (err) return done(error('server_error', false, err));
    if (!user) {
      return done(error('invalid_grant', 'User credentials are invalid'));
    }

    self.user = user;
    self.scope = self.req.body.scope;

    done();
  }, this.req);
}

/**
 * Grant for refresh_token grant type
 *
 * @param  {Function} done
 */
function useRefreshTokenGrant (done) {
  var token = this.req.body.refresh_token;

  if (!token) {
    return done(error('invalid_request', 'No "refresh_token" parameter'));
  }

  var self = this;
  this.model.getRefreshToken(token, function (err, refreshToken) {
    if (err) return done(error('server_error', false, err));

    if (!refreshToken || refreshToken.clientId !== self.client.clientId) {
      return done(error('invalid_grant', 'Invalid refresh token'));
    } else if (refreshToken.expires !== null &&
        refreshToken.expires < self.now) {
      return done(error('invalid_grant', 'Refresh token has expired'));
    }

    if (!refreshToken.user && !refreshToken.userId) {
      return done(error('server_error', false,
        'No user/userId parameter returned from getRefreshToken'));
    }

    self.user = refreshToken.user || { id: refreshToken.userId };
    self.scope = refreshToken.scope;

    if (self.model.revokeRefreshToken) {
      return self.model.revokeRefreshToken(token, function (err) {
        if (err) return done(error('server_error', false, err));
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
function useClientCredentialsGrant (done) {
  // Client credentials
  var clientId = this.client.clientId,
    clientSecret = this.client.clientSecret;

  if (!clientId || !clientSecret) {
    return done(error('invalid_client',
      'Missing parameters. "client_id" and "client_secret" are required'));
  }

  var self = this;
  return this.model.getUserFromClient(this.client, function (err, user) {
    if (err) return done(error('server_error', false, err));

    if (!user) {
      return done(error('invalid_grant', 'Client credentials are invalid'));
    }

    self.user = user;
    self.scope = self.req.body.scope || self.client.defaultScope;

    done();
  });
}

/**
 * Grant for extended (http://*) grant type
 *
 * @param  {Function} done
 */
function useExtendedGrant (done) {
  var self = this;
  this.model.extendedGrant(this.grantType, this.req,
      function (err, supported, user) {
    if (err) {
      return done(error(err.error || 'server_error',
        err.description || err.message, err));
    }

    if (!supported) {
      return done(error('invalid_request',
        'Invalid grant_type parameter or parameter missing'));
    } else if (!user || user.id === undefined) {
      return done(error('invalid_request', 'Invalid request.'));
    }

    self.user = user;
    done();
  });
}

/**
 * Grant for urn:custom:mfa-otp (http://*) grant type
 *
 * @param  {Function} done
 */
function useMfaOtpGrant (done) {
  var self = this;

  if (!self.req.body || !self.req.body.otp || !self.req.body.mfa_token) {
    return done(error('invalid_request', 'You must provide otp and mfa token.'));
  }

  this.model.performMfaOtp(this.req,
    function (err, user) {
      if (err) {
          return done(err);
      }

			convertMfaBody(self, user);

      done();
  });
}


/**
 * Grant for urn:custom:recovery-code (http://*) grant type
 *
 * @param  {Function} done
 */
function useRecoveryCodeGrant (done) {
  var self = this;

  if (!self.req.body || !self.req.body.recovery_code || !self.req.body.mfa_token) {
    return done(error('invalid_request', 'You must provide recovery code and mfa token.'));
  }

  this.model.performRecoveryCode(this.req, function (err, user) {
    if (err) {
      return done(err);
    }

    convertMfaBody(self, user);

    done();
  });
}

function convertMfaBody(self, user) {
  if (user.scope) {
    self.scope = user.scope;
  }

  if (user.client) {
    self.client = user.client;
  }

  if (self.req.body && user.expires_in) {
    self.req.body.expires_in = user.expires_in
  }

  if (self.req.body && user.expires_at !== undefined) {
    self.req.body.expires_at = user.expires_at
  }

  self.user = user;
}

/**
 * Check the grant type is allowed for this client
 *
 * @param  {Function} done
 * @this   OAuth
 */
function checkGrantTypeAllowed (done) {
  this.model.grantTypeAllowed(this.client.clientId, this.grantType,
      function (err, allowed) {
    if (err) return done(error('server_error', false, err));

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
function checkScope (done) {
  var self = this;
  this.model.validateScope(this.scope, this.client, this.user,
      function(err, scope, invalid) {
    if (err) return done(error('server_error', false, err));
    if (invalid) return done(error('invalid_scope', invalid));

    self.scope = scope;

    done();
  });
}

/**
 * Expose user
 *
 * @param  {Function} done
 * @this   OAuth
 */
function exposeUser (done) {
  this.req.user = this.user;

  done();
}

/**
 * Generate an access token
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateAccessToken (done) {
  var self = this;
  token(this, 'accessToken', function (err, token) {
    self.accessToken = token;
    done(err);
  });
}

function generateExpiresTime(done) {
	this.accessTokenLifetime = this.config.accessTokenLifetime;

	if (!this.model.generateExpiresTime) {
		return done();
	}

	var self = this;
	this.model.generateExpiresTime(this.req, function(err, expires) {
		if (err) {
			return done(error('server_error', false, err));
		}

		if (expires !== undefined) {
			self.accessTokenLifetime = expires;
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
  var accessToken = this.accessToken;

  // Object indicates a reissue
  if (typeof accessToken === 'object' && accessToken.accessToken) {
    this.accessToken = accessToken.accessToken;
    return done();
  }

  var expires = null;
  if ((this.accessTokenLifetime !== null) && (this.accessTokenLifetime > 0)) {
    expires = new Date(this.now);
    expires.setSeconds(expires.getSeconds() + this.accessTokenLifetime);
  }

  this.model.saveAccessToken(accessToken, this.client, expires,
      this.user, this.scope, this.grantType, function (err) {
    if (err) return done(error('server_error', false, err));
    done();
  });
}

/**
 * Generate a refresh token
 *
 * @param  {Function} done
 * @this   OAuth
 */
function generateRefreshToken (done) {
  if (this.config.grants.indexOf('refresh_token') === -1) return done();

  var self = this;
  token(this, 'refreshToken', function (err, token) {
    self.refreshToken = token;
    done(err);
  });
}

function generateRefreshExpiresTime(done) {
  this.refreshTokenLifetime = this.config.refreshTokenLifetime;

  if (!this.model.generateRefreshExpiresTime) {
    return done();
  }

  var self = this;
  this.model.generateRefreshExpiresTime(this.req, function(err, expires) {
    if (err) {
      return done(error('server_error', false, err));
    }

    if (expires !== undefined) {
      self.refreshTokenLifetime = expires;
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
function saveRefreshToken (done) {
  var refreshToken = this.refreshToken;

  if (!refreshToken) return done();

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

  var expires = null;
  if (this.refreshTokenLifetime) {
    expires = new Date(this.now);
    // refresh extends past access token lifetime
    expires.setSeconds(expires.getSeconds() + this.accessTokenLifetime + this.refreshTokenLifetime);
  }

  this.model.saveRefreshToken(refreshToken, this.client.clientId, expires,
      this.user, this.scope, function (err) {
    if (err) return done(error('server_error', false, err));
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
function checkMfa (done) {
  if (this.grantType !== 'password') {
    return done();
  }

  if (this.user && this.user.mfaEnabled) {
    this.model.saveMfaToken(this.user, this.req, this.client.clientId, function (err, result) {
      if (err) return done(error('server_error', false, err));
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
function sendResponse (done) {
  var response = {
    token_type: 'bearer',
    access_token: this.accessToken
  };

  if (this.accessTokenLifetime !== null) {
    response.expires_in = this.accessTokenLifetime;
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

  this.res.set({'Cache-Control': 'no-store', 'Pragma': 'no-cache'});
  this.res.jsonp(response);

  if (this.config.continueAfterResponse)
    done();
}
