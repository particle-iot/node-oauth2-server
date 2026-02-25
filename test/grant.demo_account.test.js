'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const request = require('supertest');
const { expect } = require('expect');
const OAuth2Error = require('../lib/error');
const oauth2server = require('../');

/**
 * @param {object} model
 * @param {string[]} [grants]
 * @returns {import('express')}
 */
function bootstrap(model, grants = ['urn:custom:demo_account']) {
	const app = express();
	const oauth = oauth2server({ model, grants });

	app.set('json spaces', 0);
	app.use(bodyParser());

	app.all('/oauth/token', oauth.grant());

	app.use(oauth.errorHandler());

	return app;
}

/**
 * @param {object} [overrides]
 * @returns {object}
 */
function validModel(overrides) {
	return {
		getClient: (id, secret, cb) => {
			cb(null, { clientId: 'thom', clientSecret: 'nightworld' });
		},
		grantTypeAllowed: (clientId, grantType, cb) => {
			cb(null, true);
		},
		performDemoAccountGrant: () => Promise.resolve({ id: 3, is_demo: true, expires_in: 900 }),
		saveAccessToken: (token, clientId, expires, user, scope, grantType, cb) => {
			cb();
		},
		validateScope: (scope, client, user, cb) => {
			cb(null, scope);
		},
		generateExpiresTime: (req, cb) => {
			cb(null, req && req.body && req.body.expires_in ? parseInt(req.body.expires_in) : null);
		},
		...overrides
	};
}

const minimalModel = {
	getClient: (id, secret, cb) => {
		cb(null, {});
	},
	grantTypeAllowed: (clientId, grantType, cb) => {
		cb(null, true);
	}
};

const validBody = {
	grant_type: 'urn:custom:demo_account',
	email: 'prospect@example.com',
	accepts_terms: 'true',
	client_id: 'thom',
	client_secret: 'nightworld'
};

describe('Granting with demo_account grant type', () => {
	it('should require an email address', async () => {
		const res = await request(bootstrap(minimalModel))
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send({ ...validBody, email: undefined });

		expect(res.status).toBe(400);
		expect(res.text).toMatch(/You must provide an email address/i);
	});

	it('should require accepts_terms', async () => {
		const res = await request(bootstrap(minimalModel))
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send({ ...validBody, accepts_terms: undefined });

		expect(res.status).toBe(400);
		expect(res.text).toMatch(/You must accept the demo terms of service/i);
	});

	it('should reject accepts_terms that is not the string "true"', async () => {
		const res = await request(bootstrap(minimalModel))
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send({ ...validBody, accepts_terms: 'false' });

		expect(res.status).toBe(400);
		expect(res.text).toMatch(/You must accept the demo terms of service/i);
	});

	it('should return error from performDemoAccountGrant', async () => {
		const app = bootstrap(validModel({
			performDemoAccountGrant: () => Promise.reject(new OAuth2Error('invalid_request', 'Demo access is not available.'))
		}));

		const res = await request(app)
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send(validBody);

		expect(res.status).toBe(400);
		expect(res.text).toMatch(/Demo access is not available/i);
	});

	it('should return 429 on rate_limit_exceeded error', async () => {
		const app = bootstrap(validModel({
			performDemoAccountGrant: () => Promise.reject(new OAuth2Error('rate_limit_exceeded', 'Too many demo sessions active.'))
		}));

		const res = await request(app)
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send(validBody);

		expect(res.status).toBe(429);
		expect(res.text).toMatch(/Too many demo sessions active/i);
	});

	it('should return 200 with a valid request', async () => {
		const res = await request(bootstrap(validModel()))
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send(validBody);

		expect(res.status).toBe(200);
	});

	it('should not include a refresh_token in the response', async () => {
		const app = bootstrap(
			{ ...validModel(), saveRefreshToken: (token, clientId, expires, user, cb) => {
				cb();
			} },
			['urn:custom:demo_account', 'refresh_token']
		);

		const res = await request(app)
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send(validBody);

		expect(res.status).toBe(200);
		expect(res.body).toHaveProperty('access_token');
		expect(res.body).not.toHaveProperty('refresh_token');
	});

	it('should set expires_in from the user object returned by the model', async () => {
		const res = await request(bootstrap(validModel()))
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send(validBody);

		expect(res.status).toBe(200);
		expect(res.body.expires_in).toBe(900);
	});

	it('should include an expires_at ISO string in the response', async () => {
		const res = await request(bootstrap(validModel()))
			.post('/oauth/token')
			.set('Content-Type', 'application/x-www-form-urlencoded')
			.send(validBody);

		expect(res.status).toBe(200);
		expect(typeof res.body.expires_at).toBe('string');
		expect(new Date(res.body.expires_at).toISOString()).toBe(res.body.expires_at);
	});
});
