var error = require('./error'),
  runner = require('./runner'),
  token = require('./token');

module.exports = ImplicitGrant;

var fns = [
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

  var self = this;

  runner(fns, this, function (err) {
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
  var body = this.req.body;
  var query = this.req.query;
  if (!body && !query) return done(error('invalid_request'));

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
  var self = this;
  this.model.getClient(this.clientId, null, function (err, client) {
    if (err) return done(error('server_error', false, err));

    if (!client) {
      return done(error('invalid_client', 'Invalid client credentials'));
    } else if (Array.isArray(client.redirectUri)) {
      if (client.redirectUri.indexOf(self.redirectUri) === -1) {
        return done(error('invalid_request', 'redirect_uri does not match'));
      }
      client.redirectUri = self.redirectUri;
    } else if (client.redirectUri !== self.redirectUri) {
      return done(error('invalid_request', 'redirect_uri does not match'));
    }

    // The request contains valid params so any errors after this point
    // are redirected to the redirect_uri
    self.res.redirectUri = client.redirectUri;
    self.res.oauthRedirect = true;
    self.client = client;

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
  var self = this;
  this.check(this.req, this.client, function (err, allowed, user, scope) {
    if (err) return done(error('server_error', false, err));

    if (!allowed) {
      return done(error('access_denied',
        'The user denied access to your application'));
    }

    self.user = user;
    self.scope = scope;

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
  var self = this;
  token(this, 'accessToken', function (err, atoken) {
    self.accessToken = atoken;
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
      this.user, this.scope, function (err) {
    if (err) return done(error('server_error', false, err));
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

  if (this.config.continueAfterResponse)
    return done();
}
