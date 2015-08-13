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

var error = require('./error'),
  runner = require('./runner'),
  Client = require('./client');

module.exports = Authorise;

/**
 * This is the function order used by the runner
 *
 * @type {Array}
 */
var fns = [
  checkAuthoriseType,
  checkScope
];

/**
 * Authorise
 *
 * @param {Object}   config  Instance of OAuth object
 * @param {Object}   req
 * @param {Object}   res
 * @param {Object}   options
 * @param {Function} next
 */
function Authorise (config, req, res, options, next) {
  options = options || {};

  this.config = config;
  this.model = config.model;
  this.req = req;
  this.res = res;
  this.options = options;

  runner(fns, this, next);
}

function checkAuthoriseType(done) {
  var client = Client.credsFromBasic(this.req) || Client.credsFromBody(this.req);
  if (this.options.implicit) {
    if (this.req.body.response_type === 'token') {
      if (client.clientId) {
        this.redirectUri = this.req.body.redirect_uri || this.req.query.redirect_uri;
        this.clientId = client.clientId;
        this.req.auth_type = 'implicit';
        return checkImplicitClient.call(this, done);
      }
    }
  }

  if (this.options.client_credentials) {
    if (client.clientId && client.clientSecret) {
      this.client = client;
      this.req.auth_type = 'client_credentials';
      return getUserFromClient.call(this, done);
    }
  }

  getBearerToken.call(this, done);
}

function getUserFromClient(done) {
  var self = this;
  this.model.getClient(this.client.clientId, this.client.clientSecret,
      function (err, client) {
    if (err) return done(error('server_error', false, err));

    if (!client) {
      return done(error('invalid_client', 'Client credentials are invalid'));
    }

    self.model.getUserFromClient(client, function (err, user) {
      if (err) return done(error('server_error', false, err));

      if (!user) {
        return done(error('invalid_grant', 'Client credentials are invalid'));
      }

      self.req.oauth = { bearerToken: user };
      self.req.user = { id: user.id };

      done();
    });
  });
}

function checkImplicitClient (done) {
  var self = this;
  this.model.getClient(this.clientId, null, function (err, client) {
    if (err) return done(error('server_error', false, err));

    if (!client) {
      return done(error('invalid_client', 'Invalid client credentials'));
    } else if (self.redirectUri && Array.isArray(client.redirectUri)) {
      if (client.redirectUri.indexOf(self.redirectUri) === -1) {
        return done(error('invalid_request', 'redirect_uri does not match'));
      }
      client.redirectUri = self.redirectUri;
    } else if (self.redirectUri && client.redirectUri !== self.redirectUri) {
      return done(error('invalid_request', 'redirect_uri does not match'));
    }

    self.model.getUserFromClient(client, function (err, user) {
      if (err) return done(error('server_error', false, err));

      if (!user) {
        return done(error('invalid_grant', 'Client credentials are invalid'));
      }

      // The request contains valid params so any errors after this point
      // are redirected to the redirect_uri
      self.res.redirectUri = client.redirectUri;
      self.res.oauthRedirect = true;
      self.req.oauth = { bearerToken: user };
      self.req.user = { id: user.id };


      done();
    });
  });
}

/**
 * Get bearer token
 *
 * Extract token from request according to RFC6750
 *
 * @param  {Function} done
 * @this   OAuth
 */
function getBearerToken (done) {
  var headerToken = this.req.get('Authorization'),
    getToken =  this.req.query.access_token,
    postToken = this.req.body ? this.req.body.access_token : undefined;

  // Check exactly one method was used
  var methodsUsed = (headerToken !== undefined) + (getToken !== undefined) +
    (postToken !== undefined);

  if (methodsUsed > 1) {
    return done(error('invalid_request',
      'Only one method may be used to authenticate at a time (Auth header,  ' +
        'GET or POST).'));
  } else if (methodsUsed === 0) {
    return done(error('invalid_request', 'The access token was not found'));
  }

  // Header: http://tools.ietf.org/html/rfc6750#section-2.1
  if (headerToken) {
    var matches = headerToken.match(/Bearer\s(\S+)/);

    if (!matches) {
      return done(error('invalid_request', 'Malformed auth header'));
    }

    headerToken = matches[1];
  }

  // POST: http://tools.ietf.org/html/rfc6750#section-2.2
  if (postToken) {
    if (this.req.method === 'GET') {
      return done(error('invalid_request',
        'Method cannot be GET When putting the token in the body.'));
    }

    if (!this.req.is('application/x-www-form-urlencoded')) {
      return done(error('invalid_request', 'When putting the token in the ' +
        'body, content type must be application/x-www-form-urlencoded.'));
    }
  }

  this.bearerToken = headerToken || postToken || getToken;
  checkToken.call(this, done);
}

/**
 * Check token
 *
 * Check it against model, ensure it's not expired
 * @param  {Function} done
 * @this   OAuth
 */
function checkToken (done) {
  var self = this;
  this.model.getAccessToken(this.bearerToken, function (err, token) {
    if (err) return done(error('server_error', false, err));

    if (!token) {
      return done(error('invalid_token',
        'The access token provided is invalid.'));
    }

    if (token.expires !== null &&
      (!token.expires || token.expires < new Date())) {
      return done(error('invalid_token',
        'The access token provided has expired.'));
    }

    // Expose params
    self.req.oauth = { bearerToken: token };
    self.req.user = token.user ? token.user : { id: token.userId };

    done();
  });
}

/**
 * Check scope
 *
 * @param {Function} done
 * @this  OAuth
 */

function checkScope (done) {
  if (!this.model.authoriseScope) return done();

  this.model.authoriseScope(this.req.oauth.bearerToken, this.options.scope,
      function (err, invalid) {
    if (err) return done(error('server_error', false, err));
    if (invalid) return done(error('invalid_scope', invalid));

    done();
  });
}
