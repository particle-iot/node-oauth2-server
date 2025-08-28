var express = require('express'),
	bodyParser = require('body-parser'),
	request = require('supertest'),
	should = require('should'),
	OAuth2Error = require('../lib/error');

var oauth2server = require('../');

var bootstrap = function (oauthConfig) {
	var app = express(),
		oauth = oauth2server(oauthConfig || {
			model: {},
			grants: ['password', 'refresh_token', 'urn:custom:mfa-otp']
		});

	app.set('json spaces', 0);
	app.use(bodyParser());

	app.all('/oauth/token', oauth.grant());

	app.use(oauth.errorHandler());

	return app;
};

describe('Granting with recovery-code grant type', function () {
	it('should still detect unsupported grant_type', function (done) {
		var app = bootstrap({
			model: {
				getClient: function (id, secret, callback) {
					callback(false, true);
				},
				grantTypeAllowed: function (clientId, grantType, callback) {
					callback(false, true);
				},
				extendedGrant: function (grantType, req, callback) {
					callback(false, false);
				}
			},
			grants: ['http://custom.com']
		});

		request(app)
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send({
				grant_type: 'http://custom.com',
				client_id: 'thom',
				client_secret: 'nightworld'
			})
			.expect(400, /invalid grant_type/i, done);
	});

	it('should require an mfa_token', function (done) {
		var app = bootstrap({
			model: {
				getClient: function (id, secret, callback) {
					callback(false, true);
				},
				grantTypeAllowed: function (clientId, grantType, callback) {
					callback(false, true);
				}
			},
			grants: ['urn:custom:recovery-code']
		});

		request(app)
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send({
				grant_type: 'urn:custom:recovery-code',
				recovery_code: '123456',
				client_id: 'thom',
				client_secret: 'nightworld'
			})
			.expect(400, /You must provide recovery code and mfa token/i, done);
	});

	it('should require a recovery code', function (done) {
		var app = bootstrap({
			model: {
				getClient: function (id, secret, callback) {
					callback(false, true);
				},
				grantTypeAllowed: function (clientId, grantType, callback) {
					callback(false, true);
				}
			},
			grants: ['urn:custom:recovery-code']
		});

		request(app)
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send({
				grant_type: 'urn:custom:recovery-code',
				mfa_token: '123456',
				client_id: 'thom',
				client_secret: 'nightworld'
			})
			.expect(400, /You must provide recovery code and mfa token/i, done);
	});

	it('should return error from performMfaOtp', function (done) {
		var app = bootstrap({
			model: {
				getClient: function (id, secret, cb) {
					cb(false, { clientId: 'thom', clientSecret: 'nightworld' });
				},
				grantTypeAllowed: function (clientId, grantType, cb) {
					cb(false, true);
				},
				useMfaOtpGrant: function (grantType, req, cb) {
					req.oauth.client.clientId.should.equal('thom');
					req.oauth.client.clientSecret.should.equal('nightworld');
					cb(false, true, { id: 3 });
				},
				saveAccessToken: function (token, clientId, expires, user, scope, grantType, cb) {
					cb();
				},
				validateScope: function (scope, client, user, cb) {
					cb(false, '', false);
				},
				performRecoveryCode: function (req, cb) {
					cb(new OAuth2Error('invalid_token', 'Could not validate Recovery Code.'));
				}
			},
			grants: ['urn:custom:recovery-code']
		});

		request(app)
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send({
				grant_type: 'urn:custom:recovery-code',
				client_id: 'thom',
				client_secret: 'nightworld',
				mfa_token: '123456',
				recovery_code: '123456'
			})
			.expect(401, /Could not validate Recovery Code/i, done);
	});

	it('should passthrough valid request', function (done) {
		var app = bootstrap({
			model: {
				getClient: function (id, secret, cb) {
					cb(false, { clientId: 'thom', clientSecret: 'nightworld' });
				},
				grantTypeAllowed: function (clientId, grantType, cb) {
					cb(false, true);
				},
				useMfaOtpGrant: function (grantType, req, cb) {
					req.oauth.client.clientId.should.equal('thom');
					req.oauth.client.clientSecret.should.equal('nightworld');
					cb(false, true, { id: 3 });
				},
				saveAccessToken: function (token, clientId, expires, user, scope, grantType, cb) {
					cb();
				},
				validateScope: function (scope, client, user, cb) {
					cb(false, '', false);
				},
				performRecoveryCode: function (req, cb) {
					cb(false, true, { id: 3 });
				}
			},
			grants: ['urn:custom:recovery-code']
		});

		request(app)
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send({
				grant_type: 'urn:custom:recovery-code',
				client_id: 'thom',
				client_secret: 'nightworld',
				mfa_token: '123456',
				recovery_code: '123456'
			})
			.expect(200, done);
	});

  it('should return the rate_limit error', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, cb) {
          cb(false, { clientId: 'thom', clientSecret: 'nightworld' });
        },
        grantTypeAllowed: function (clientId, grantType, cb) {
          cb(false, true);
        },
        useMfaOtpGrant: function (grantType, req, cb) {
          req.oauth.client.clientId.should.equal('thom');
          req.oauth.client.clientSecret.should.equal('nightworld');
          cb(false, true, { id: 3 });
        },
        saveAccessToken: function (token, clientId, expires, user, scope, grantType, cb) {
          cb();
        },
        validateScope: function (scope, client, user, cb) {
          cb(false, '', false);
        },
        performRecoveryCode: function (req, cb) {
          cb(new OAuth2Error('rate_limit_exceeded', 'Rate limit exceeded.'));
        }
      },
      grants: ['urn:custom:recovery-code']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grant_type: 'urn:custom:recovery-code',
        client_id: 'thom',
        client_secret: 'nightworld',
        mfa_token: '123456',
        recovery_code: '123456'
      })
      .expect(429, /Rate limit exceeded./i, done);
  });
});
