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
      grants: ['client_credentials']
    });

  app.set('json spaces', 0);
  app.use(bodyParser());

  app.all('/oauth/token', oauth.grant());

  app.use(oauth.errorHandler());

  return app;
};

describe('Granting with client_credentials grant type', function () {

  // N.B. Client is authenticated earlier in request

  it('should detect invalid user', function (done) {
    var app = bootstrap({
      model: {
        getClient: function (id, secret, callback) {
          callback(false, { clientId: id });
        },
        grantTypeAllowed: function (clientId, grantType, callback) {
          callback(false, true);
        },
        getUserFromClient: function (client, callback) {
          client.clientId.should.equal('thom');
          client.clientSecret.should.equal('nightworld');
          callback(false, false); // Fake invalid user
        }
      },
      grants: ['client_credentials']
    });

    request(app)
      .post('/oauth/token')
      .set('Content-Type', 'application/x-www-form-urlencoded')
      .send({
        grant_type: 'client_credentials'
      })
      .set('Authorization', 'Basic dGhvbTpuaWdodHdvcmxk')
      .expect(400, /client credentials are invalid/i, done);

  });

it('should bypass the MFA check', function (done) {
  var app = bootstrap({
    model: {
      getClient: function (id, secret, callback) {
        callback(false, { clientId: id });
      },
      grantTypeAllowed: function (clientId, grantType, callback) {
        callback(false, true);
      },
			getUserFromClient: function (client, callback) {
        client.clientId.should.equal('thom');
        client.clientSecret.should.equal('nightworld');
        callback(false, { id: 1, mfaEnabled: true });
      },
      validateScope: function (scope, client, user, cb) {
        cb(false, '', false);
      },
      saveAccessToken: function (token, clientId, expires, user, scope, grantType, cb) {
        cb();
      },
    },
    grants: ['client_credentials']
  });

  request(app)
    .post('/oauth/token')
    .set('Content-Type', 'application/x-www-form-urlencoded')
    .send({
      grant_type: 'client_credentials'
    })
    .set('Authorization', 'Basic dGhvbTpuaWdodHdvcmxk')
    .expect(200, /"access_token":"(.*)",(.*)"/i, done);

  });
});
