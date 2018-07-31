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

var express = require('express'),
  bodyParser = require('body-parser'),
  request = require('supertest'),
  should = require('should');

var oauth2server = require('../');

var bootstrap = function (oauthConfig) {
  var app = express(),
    oauth = oauth2server(oauthConfig || {
      model: {},
      grants: ['password', 'refresh_token']
    });

  app.set('json spaces', 0);
  app.use(bodyParser());

  app.all('/oauth/token', oauth.grant());

  app.use(oauth.errorHandler());

  return app;
};

describe('Granting with password grant type', function () {
  it('should detect missing parameters', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, true);
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        }
      },
      grants: ['password']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grant_type: 'password',
        client_id: 'thom',
        client_secret: 'nightworld'
      })
      .expect(400, /missing parameters. \\"username\\" and \\"password\\"/i, done);

  });

  it('should detect invalid user', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, true);
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        },
        getUser: function (uname, pword, callback) {
          uname.should.equal('thomseddon');
          pword.should.equal('nightworld');
          callback(false, false); // Fake invalid user
        }
      },
      grants: ['password']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grant_type: 'password',
        client_id: 'thom',
        client_secret: 'nightworld',
        username: 'thomseddon',
        password: 'nightworld'
      })
      .expect(400, /user credentials are invalid/i, done);

  });

  it('should detect mfa needed and return an error', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, true);
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        },
        getUser: function (uname, pword, callback) {
          callback(false, { id: 1, mfaEnabled: true });
        },
        validateScope: function(scope, client, user, cb) {
          cb(false, 'foo bar', false);
        },
        saveMfaToken: function(user, req, clientId, cb) {
          cb(false, { mfa_token: '12345678' } );
        }
      },
      grants: ['password']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grant_type: 'password',
        client_id: 'thom',
        client_secret: 'nightworld',
        username: 'thomseddon',
        password: 'nightworld'
      })
      .expect(403, /Multi-factor authentication required/i, done);
    });

  it('should pass through mfa if not needed', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, true);
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        },
        getUser: function (uname, pword, callback) {
          callback(false, { id: 1, mfaEnabled: false });
        },
        saveAccessToken: function (token, client, expires, user, scope, grantType, cb) {
          cb();
        },
        validateScope: function(scope, client, user, cb) {
          cb(false, 'foo bar', false);
        },
      },
      grants: ['password']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grant_type: 'password',
        client_id: 'thom',
        client_secret: 'nightworld',
        username: 'thomseddon',
        password: 'nightworld'
      })
      .expect(200, /"access_token":"(.*)",(.*)"/i, done);
  });
});
