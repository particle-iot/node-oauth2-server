'use strict';

var auth = require('basic-auth');

/**
 * Client Object (internal use only)
 *
 * @param {String} id     client_id
 * @param {String} secret client_secret
 */
function Client (id, secret) {
  this.clientId = id;
  this.clientSecret = secret;
}

/**
 * Extract client creds from Basic auth
 *
 * @return {Object} Client
 */
function credsFromBasic (req) {
  var user = auth(req);

  if (!user) return false;

  return new Client(user.name, user.pass);
}

/**
 * Extract client creds from body
 *
 * @return {Object} Client
 */
function credsFromBody (req) {
  return new Client(req.body.client_id, req.body.client_secret);
}

module.exports = Client;
module.exports.credsFromBasic = credsFromBasic;
module.exports.credsFromBody = credsFromBody;
