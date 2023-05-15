/* eslint-disable no-console */

import * as path from 'node:path';
import { promisify } from 'node:util';

import { dirname } from 'desm';
import render from '@koa/ejs';
import helmet from 'helmet';
import { Strategy } from 'openid-client';
import Provider from '../lib/index.js'; // from 'oidc-provider';
import passport from 'passport';
import Account from './support/account.js';
import configuration from './support/configuration.js';
import routes from './routes/koa.js';
import fs from 'fs'
import https from 'https';
import { sign, verify, anchor, DID, generateKeyPair, resolve } from '@decentralized-identity/ion-tools';
import {importJWK, compactVerify} from 'jose';
import { v4 as uuidv4 } from 'uuid';
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
const key  = fs.readFileSync('key.pem', 'utf8');
const cert = fs.readFileSync('cert.pem', 'utf8');
const baseUrl = process.env.ISSUER || "https://openid-provider.com";
// openid-provider DID: did:ion:EiBr3cl0yOq4TDkQ-AioibD8NF2Miml3BQ-40smk5Viu0Q
const ID = "did:ion:EiBr3cl0yOq4TDkQ-AioibD8NF2Miml3BQ-40smk5Viu0Q";
const WALLET_URI = `https://siop-wallet.com:3002`;
const USE_DID = true;

const srvOptions = {
  key: key,
  cert: cert
};

var config = {
  domain: 'openid-provider.com',
  http: {
    port: 8989,
  },
  https: {
    port: 3000,
    options: {
      key: fs.readFileSync(path.resolve(process.cwd(), 'key.pem'), 'utf8').toString(),
      cert: fs.readFileSync(path.resolve(process.cwd(), 'cert.pem'), 'utf8').toString(),
    },
  },
};



const __dirname = dirname(import.meta.url);

const { PORT = 3000, ISSUER = `https://openid-provider.com:${PORT}` } = process.env;
configuration.findAccount = Account.findAccount;

let server;

const getDateEpoch = () => {
  const now = new Date()  
  const utcMilllisecondsSinceEpoch = now.getTime() + (now.getTimezoneOffset() * 60 * 1000)  
  const utcSecondsSinceEpoch = Math.round(utcMilllisecondsSinceEpoch / 1000)  
  return utcSecondsSinceEpoch;
};

const createRequestObject = async (state, nonce) => {
  const privateJwk  = JSON.parse(fs.readFileSync('did-private.json', 'utf8'));
  const alg = "ES256K";
  const iat = getDateEpoch();
  const header = {
    "kid": `${ID}#key-1`,
    "alg": alg,
    "typ":"oauth-authz-req+jwt"
  }
  const body = {
    "client_id": `${ID}`,
    "client_id_scheme": "did",
    "iss": ID,
    "nbf": iat,
    "iat": iat,
    "jti": `${ID}-${uuidv4()}`,
    "response_type": "id_token vp_token",
    "redirect_uri": `${baseUrl}:${PORT}/interaction/callback/wallet`,
    "nonce": nonce,
    "scope": "openid",
    "state" :state,
    "presentation_definition": {
      "id": uuidv4(),
      "input_descriptors": [{
        "id": "name credential",
        "format": {
          "jwt_vp": {
            "alg": [
              "ES256K"
            ]
          }
        },
        "constraints": {
          "fields": [{
            "path": ["$.type"],
            "filter": {
              "type": "string",
              "pattern": "IDCardCredential"
            }
          }]
        }
      }]
    }
  }
  const jws = await sign({ header: header, payload: body, privateJwk });
  return jws;
};

const isValidSignature = async (alg, jwt, publicJwk) => {
  const publicKey = await importJWK(publicJwk, alg);
  let verSig = undefined;
  let isValid = false;
  try {
    verSig = await compactVerify(jwt, publicKey)
    if(verSig) {
      isValid = true;
    }
  } catch(error) {
    isValid = false;
    console.log(error)
  }
  return isValid; 
};

try {
  let adapter;
  if (process.env.MONGODB_URI) {
    ({ default: adapter } = await import('./adapters/mongodb.js'));
    await adapter.connect();
  }

  const prod = process.env.NODE_ENV === 'production';

  const provider = new Provider(ISSUER, { adapter, ...configuration });


  // wallet federation initialization
  if (USE_DID) {
    const openid = await import('openid-client'); // eslint-disable-line import/no-unresolved
    const wallet = new openid.Issuer({"authorization_endpoint":`${WALLET_URI}/authorize`});
    const state = uuidv4();
    const nonce = uuidv4();
    let walletClient = new wallet.Client({
      request: await createRequestObject(state, nonce),
      state: state,
      nonce: nonce,
      client_id: ID,
      response_types: ['id_token'],
      redirect_uris: [`${ISSUER}/interaction/callback/wallet`],
      grant_types: ['implicit']
    });
    provider.app.context.wallet = walletClient;
  }

  // don't wanna re-bundle the interactions so just insert the login amr and acr as static whenever
  // login is submitted, usually you would submit them from your interaction
  const { interactionFinished } = provider;
  provider.interactionFinished = (...args) => {
    const { login } = args[2];
    if (login) {
      Object.assign(args[2].login, {
        acr: 'urn:mace:incommon:iap:bronze',
        amr: login.accountId.startsWith('google.') ? ['google'] : ['pwd'],
      });
    }

    return interactionFinished.call(provider, ...args);
  };

  const directives = helmet.contentSecurityPolicy.getDefaultDirectives();
  delete directives['form-action'];
  const pHelmet = promisify(helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives,
    },
  }));

  provider.use(async (ctx, next) => {
    const origSecure = ctx.req.secure;
    ctx.req.secure = ctx.request.secure;
    await pHelmet(ctx.req, ctx.res);
    ctx.req.secure = origSecure;
    return next();
  });

  if (prod) {
    provider.proxy = true;
    provider.use(async (ctx, next) => {
      if (ctx.secure) {
        await next();
      } else if (ctx.method === 'GET' || ctx.method === 'HEAD') {
        ctx.status = 303;
        ctx.redirect(ctx.href.replace(/^http:\/\//i, 'https://'));
      } else {
        ctx.body = {
          error: 'invalid_request',
          error_description: 'do yourself a favor and only use https',
        };
        ctx.status = 400;
      }
    });
  }
  render(provider.app, {
    cache: false,
    viewExt: 'ejs',
    layout: '_layout',
    root: path.join(__dirname, 'views'),
  });
  provider.use(routes(provider).routes());
  let serverCallback = provider.callback();
  server = https.createServer(srvOptions, serverCallback);
  let httpsServer = https.createServer(config.https.options, serverCallback);
  server = httpsServer.listen(PORT, () => {
    console.log(`application is listening on port ${PORT}, check its /.well-known/openid-configuration`);
  });
} catch (err) {
  if (server?.listening) server.close();
  console.error(err);
  process.exitCode = 1;
}
