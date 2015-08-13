var express = require('express'),
  bodyParser = require('body-parser'),
  request = require('supertest'),
  should = require('should');

var oauth2server = require('../');

var bootstrap = function (model, params, continueAfterResponse) {

  var app = express();
  app.oauth = oauth2server({
    model: model || {},
    continueAfterResponse: continueAfterResponse
  });

  app.use(bodyParser());

  app.post('/authorise', app.oauth.implicit(function (req, client, next) {
    next.apply(null, params || []);
  }));

  app.get('/authorise', app.oauth.implicit(function (req, client, next) {
    next.apply(null, params || []);
  }));

  app.use(app.oauth.errorHandler());

  return app;
};

describe('ImplicitGrant', function() {
  it('should try to save access token', function (done) {
    var app = bootstrap({
      getClient: function (clientId, clientSecret, callback) {
        callback(false, {
          clientId: 'thom',
          redirectUri: 'http://nightworld.com'
        });
      },
      saveAccessToken: function (accessToken, client, expires, user, scope, callback) {
        should.exist(accessToken);
        accessToken.should.have.lengthOf(40);
        client.clientId.should.equal('thom');
        (+expires).should.be.within(2, (+new Date()) + 3600000);
        done();
      }
    }, [false, true]);

    request(app)
      .post('/authorise')
      .send({
        response_type: 'token',
        client_id: 'thom',
        redirect_uri: 'http://nightworld.com'
      })
      .end();
  });

  it('should accept valid request and return token using POST', function (done) {
    var token;

    var app = bootstrap({
      getClient: function (clientId, clientSecret, callback) {
        callback(false, {
          clientId: 'thom',
          redirectUri: 'http://nightworld.com'
        });
      },
      saveAccessToken: function (accessToken, client, expires, user, scope, callback) {
        should.exist(accessToken);
        token = accessToken;
        callback();
      }
    }, [false, true]);

    request(app)
      .post('/authorise')
      .send({
        response_type: 'token',
        client_id: 'thom',
        redirect_uri: 'http://nightworld.com'
      })
      .expect(302, function (err, res) {
        if (err) {
          return done(err);
        }
        res.header.location.should.equal('http://nightworld.com#token=' + token);
        done();
      });
  });

  it('should accept valid request and return token using GET', function (done) {
    var token;

    var app = bootstrap({
      getClient: function (clientId, clientSecret, callback) {
        callback(false, {
          clientId: 'thom',
          redirectUri: 'http://nightworld.com'
        });
      },
      saveAccessToken: function (accessToken, client, expires, user, scope, callback) {
        should.exist(accessToken);
        token = accessToken;
        callback();
      }
    }, [false, true]);

    request(app)
      .get('/authorise')
      .query({
        response_type: 'token',
        client_id: 'thom',
        redirect_uri: 'http://nightworld.com'
      })
      .expect(302, function (err, res) {
        if (err) {
          return done(err);
        }
        res.header.location.should.equal('http://nightworld.com#token=' + token);
        done();
      });
  });
});