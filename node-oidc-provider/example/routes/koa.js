/* eslint-disable no-console, camelcase, no-unused-vars */
import { strict as assert } from 'node:assert';
import * as querystring from 'node:querystring';
import * as crypto from 'node:crypto';
import { inspect } from 'node:util';

import isEmpty from 'lodash/isEmpty.js';
import { koaBody as bodyParser } from 'koa-body';
import Router from 'koa-router';

import { defaults } from '../../lib/helpers/defaults.js'; // make your own, you'll need it anyway
import Account from '../support/account.js';
import { errors } from '../../lib/index.js'; // from 'oidc-provider';

import * as jose from 'jose'
import { sign, verify, anchor, DID, generateKeyPair, resolve } from '@decentralized-identity/ion-tools';

import { default as Configuration } from "../support/configuration.js";


const getDateEpoch = () => {
  const now = new Date()  
  const utcMilllisecondsSinceEpoch = now.getTime() + (now.getTimezoneOffset() * 60 * 1000)  
  const utcSecondsSinceEpoch = Math.round(utcMilllisecondsSinceEpoch / 1000)  
  return utcSecondsSinceEpoch;
};

const isValidDate = (body) => {
  const exp = body.exp || undefined;
  const now = getDateEpoch();
  if(exp) {
    return (now >= body.iat) &&
  (now >=body.nbf) && (now <= exp);
  } else {
    return (now >= body.iat) &&
    (now >=body.nbf);
  }
  
};


const isValidCredJwt = (jwt, walletDID) =>  {
  const header = JSON.parse(Buffer.from(jwt.split(".")[0], 'base64').toString('utf8'));
  const body = JSON.parse(Buffer.from(jwt.split(".")[1], 'base64').toString('utf8'));
  const keyId = header.kid;
  const did = keyId.split("#")[0];
  if(did != body.iss) {
    console.log("issuer and did in header are not the same");
    return false;
  }
  if(!isValidDate(body)) {
    console.log("token is not yet active, expired or contains otherwise false time signature.");
    return false;
  }
  if(body.sub != walletDID) {
    console.log("Credential subject mismatch from wallet");
    return false;
  }
  console.log("Valid DID JWT")
  return true;
};

const getPublicKeyFromDocument = (doc, keyId) => {
  console.log("public key from did document method")
  const verificationMethod = doc.didDocument.verificationMethod;
  const keyResult = verificationMethod.filter(key => (key.id == keyId) || (key.id == `#${keyId}`)).pop();
  if(keyResult) {
    // key found
    const publicJwk = keyResult.publicKeyJwk;
    return publicJwk;
  } else {
    // key not found
    console.log("key not found");
    return {};
  }
};

const parseJwt = async (jwt) => {
  const header = JSON.parse(Buffer.from(jwt.split(".")[0], 'base64').toString('utf8'));
  const body = JSON.parse(Buffer.from(jwt.split(".")[1], 'base64').toString('utf8'));
  const kid = header.kid;
  let doc = undefined;
  let publicJwk;
  let validSignature = false;
  if(kid.indexOf("did:") >= 0) {
    // public key needs to be aquired from did document
    const did = kid.split("#")[0];
    const keyId = `#${kid.split("#")[1]}`;
    doc = await resolve(did);
    publicJwk = getPublicKeyFromDocument(doc, keyId);
    validSignature = await isValidSignature(header.alg, jwt, publicJwk);
    console.log("is valid signature: " + validSignature);
    return validSignature;
  } else {
    return false;
  }
};

const isValidSignature = async (alg, jwt, publicJwk) => {
  const publicKey = await jose.importJWK(publicJwk, alg);
  let verSig = undefined;
  let isValid = false;
  if(alg.toLowerCase() == "none") {
    return isValid; 
  }
  try {
    verSig = await jose.compactVerify(jwt, publicKey)
    if(verSig) {
      isValid = true;
    }
  } catch(error) {
    isValid = false;
    console.log(error)
  }
  return isValid; 
}


const keys = new Set();
const debug = (obj) => querystring.stringify(Object.entries(obj).reduce((acc, [key, value]) => {
  keys.add(key);
  if (isEmpty(value)) return acc;
  acc[key] = inspect(value, { depth: null });
  return acc;
}, {}), '<br/>', ': ', {
  encodeURIComponent(value) { return keys.has(value) ? `<strong>${value}</strong>` : value; },
});

const { SessionNotFound } = errors;

const isTrustedIssuer = (iss) => {
  const strict = Configuration.vcIssuerPolicies.strict;
  const trustedIssuerDID = Configuration.vcIssuerPolicies.trustedIssuerDID;
  // if no issuer checking
  if(!strict) {
    console.log("strict is false: no issuer checking");
    return true;
  } else {
    const trusted = trustedIssuerDID.includes(iss);
    console.log(`The Verifiable Credential Issuer (DID: ${iss}) is trusted: ${trusted}`);
    return trusted;
  }
};

function serialize( obj ) {
  let str = '?' + Object.keys(obj).reduce(function(a, k){
      a.push(k + '=' + encodeURIComponent(obj[k]));
      return a;
  }, []).join('&');
  return str;
}

export default (provider) => {
  const router = new Router();

  router.use(async (ctx, next) => {
    ctx.set('cache-control', 'no-store');
    try {
      await next();
    } catch (err) {
      if (err instanceof SessionNotFound) {
        ctx.status = err.status;
        const { message: error, error_description } = err;
        await defaults.renderError(ctx, { error, error_description }, err);
      } else {
        throw err;
      }
    }
  });

  router.get('/interaction/:uid', async (ctx, next) => {
    const {
      uid, prompt, params, session,
    } = await provider.interactionDetails(ctx.req, ctx.res);
    const client = await provider.Client.find(params.client_id);
    if(ctx.wallet) {
      ctx.wallet.rp_nonce = params.nonce || undefined
      ctx.wallet.rp_state = params.state || undefined;
      ctx.wallet.rp_redirect_uri = params.redirect_uri || undefined;
    }

    switch (prompt.name) {
      
      case 'login': {
        return ctx.render('login', {
          client,
          uid,
          details: prompt.details,
          params,
          title: 'Sign-in',
          wallet: ctx.wallet,
          google: ctx.google,
          session: session ? debug(session) : undefined,
          dbg: {
            params: debug(params),
            prompt: debug(prompt),
          },
        });
      }
      case 'consent': {
        return ctx.render('interaction', {
          client,
          uid,
          details: prompt.details,
          params,
          title: 'Authorize',
          session: session ? debug(session) : undefined,
          dbg: {
            params: debug(params),
            prompt: debug(prompt),
          },
        });
      }
      default:
        return next();
    }
  });

  const body = bodyParser({
    text: false, json: false, patchNode: true, patchKoa: true,
  });

  router.get('/interaction/callback/wallet', async (ctx) => {
    const wallet = provider.app.context.wallet;
    const rpNonce = wallet.rp_nonce || undefined;
    const rpState = wallet.rp_state || undefined;
    const rpRedirect = wallet.rp_redirect_uri || undefined;
    const search = ctx.res.req._parsedUrl.search;
    const params = new URLSearchParams(search);
    const error = params.get("error") || undefined;
    if(error) {
      const description = params.get("error_description");
      console.log(error);
      console.log(description)
      return ctx.redirect(`${rpRedirect}?error=${error}&error_description=${description}`)
    }

    const idToken = params.get("id_token") || undefined;
    const presentationSubmission = params.get("presentation_submission") || undefined;
    const vpToken = params.get("vp_token") || undefined;
    const state = params.get("state") || undefined;
    const idBody = JSON.parse(Buffer.from(idToken.split(".")[1], 'base64').toString('utf8')) || undefined;
    const vpBody = JSON.parse(Buffer.from(vpToken.split(".")[1], 'base64').toString('utf8')) || undefined;
    const credential = vpBody.vp.verifiableCredential[0];

    const vcBody = JSON.parse(Buffer.from(credential.split(".")[1], 'base64').toString('utf8')) || undefined;
    if(!isTrustedIssuer(vcBody.iss)) {
      return ctx.redirect(`${rpRedirect}?error=Issuer Error&error_description=The Verifiable Credential is from untrusted issuer`)
    }

    const validIdTokenSignature = await parseJwt(idToken);
    const validVpTokenSignature = await parseJwt(vpToken);
    const validCredentialSignature = await parseJwt(credential);
    console.log("validIdTokenSignature",validIdTokenSignature);
    console.log("validVpTokenSignature",validVpTokenSignature);
    console.log("validCredentialSignature",validCredentialSignature);
    const walletDID = vpBody.iss;
    const validCred = isValidCredJwt(credential, walletDID);
    console.log("validCred",validCred);

    const nonce = idBody.nonce;
    try {
      // state and nonce checks
      if(nonce != vpBody.nonce && nonce != wallet.nonce) {
        return ctx.redirect(`${rpRedirect}?error=Nonce Error&error_description=Nonce mismatch`);
      }
      if(state != wallet.state) {
        return ctx.redirect(`${rpRedirect}?error=State Error&error_description=State mismatch`);
      }
    } catch(error) {
      return ctx.redirect(`${rpRedirect}?error=State or Nonce Error&error_description=State or Nonce mismatch`);
    }

    if(!validIdTokenSignature || !validVpTokenSignature || !validCredentialSignature) {
      console.log("Invalid signature");
      return ctx.redirect(`${rpRedirect}?error=Signature Error&error_description=Invalid Signature`);
    }
    if(!validCred) {
      console.log("Credential Error");
      return ctx.redirect(`${rpRedirect}?error=Credential Error&error_description=Invalid Credential`);
    }

    const callbackParams = wallet.callbackParams(ctx.req);
    
    // after token validation change the idBody to contain more content, i.e., from vp token (VC)
    idBody.credentialSubject = vcBody.vc.credentialSubject;

    const account = await Account.findByWalletFederated('wallet', idBody);
    const path = `/interaction/${wallet.interaction}/federated`
    ctx.cookies.set('interaction', wallet.interaction, { path, sameSite: 'strict' });
    let headerCookie = ctx.request.header.cookie;
    headerCookie += `_interaction=${wallet.interaction}`
    
    const result = {
      login: {
        accountId: account.accountId,
      },
    };
    return provider.interactionFinished(ctx.req, ctx.res, result, {
      mergeWithLastSubmission: false,
    });
  });

  

  router.get('/interaction/callback/google', (ctx) => {
    const nonce = ctx.res.locals.cspNonce;
    return ctx.render('repost', { layout: false, upstream: 'google', nonce });
  });

  router.post('/interaction/:uid/login', body, async (ctx) => {
    const { prompt: { name } } = await provider.interactionDetails(ctx.req, ctx.res);
    assert.equal(name, 'login');

    const account = await Account.findByLogin(ctx.request.body.login);

    const result = {
      login: {
        accountId: account.accountId,
      },
    };
    return provider.interactionFinished(ctx.req, ctx.res, result, {
      mergeWithLastSubmission: false,
    });
  });

  
  router.post('/interaction/:uid/federated', body, async (ctx) => {
    const { prompt: { name } } = await provider.interactionDetails(ctx.req, ctx.res);
    assert.equal(name, 'login');
    const path = `/interaction/${ctx.params.uid}/federated`;
    switch (ctx.request.body.upstream) {
      case 'wallet': {
        console.log("wallet interaction")
        ctx.wallet.interaction = ctx.params.uid;
        const callbackParams = ctx.wallet.callbackParams(ctx.req);
        const request = ctx.wallet.request;
        // init
        if (!Object.keys(callbackParams).length) {
          const state = `${ctx.wallet.state}` || `${crypto.randomBytes(32).toString('hex')}`;
          const nonce = `${ctx.wallet.nonce}` || `${crypto.randomBytes(32).toString('hex')}`;
          ctx.cookies.set('wallet.state', state, { path, sameSite: 'strict' });
          ctx.cookies.set('wallet.nonce', nonce, { path, sameSite: 'strict' });
          ctx.status = 303;
          return ctx.redirect(ctx.wallet.authorizationUrl({
            request,  scope: 'openid profile',
          }));
        }
      }
      case 'google': {
        const callbackParams = ctx.google.callbackParams(ctx.req);

        // init
        if (!Object.keys(callbackParams).length) {
          const state = `${ctx.params.uid}|${crypto.randomBytes(32).toString('hex')}`;
          const nonce = crypto.randomBytes(32).toString('hex');

          ctx.cookies.set('google.state', state, { path, sameSite: 'strict' });
          ctx.cookies.set('google.nonce', nonce, { path, sameSite: 'strict' });

          ctx.status = 303;
          return ctx.redirect(ctx.google.authorizationUrl({
            state, nonce, scope: 'openid email profile',
          }));
        }

        // callback
        const state = ctx.cookies.get('google.state');
        ctx.cookies.set('google.state', null, { path });
        const nonce = ctx.cookies.get('google.nonce');
        ctx.cookies.set('google.nonce', null, { path });

        const tokenset = await ctx.google.callback(undefined, callbackParams, { state, nonce, response_type: 'id_token' });
        const account = await Account.findByFederated('google', tokenset.claims());

        const result = {
          login: {
            accountId: account.accountId,
          },
        };
        return provider.interactionFinished(ctx.req, ctx.res, result, {
          mergeWithLastSubmission: false,
        });
      }
      default:
        return undefined;
    }
  });

  router.post('/interaction/:uid/confirm', body, async (ctx) => {
    const interactionDetails = await provider.interactionDetails(ctx.req, ctx.res);
    const { prompt: { name, details }, params, session: { accountId } } = interactionDetails;
    assert.equal(name, 'consent');

    let { grantId } = interactionDetails;
    let grant;

    if (grantId) {
      // we'll be modifying existing grant in existing session
      grant = await provider.Grant.find(grantId);
    } else {
      // we're establishing a new grant
      grant = new provider.Grant({
        accountId,
        clientId: params.client_id,
      });
    }

    if (details.missingOIDCScope) {
      grant.addOIDCScope(details.missingOIDCScope.join(' '));
    }
    if (details.missingOIDCClaims) {
      grant.addOIDCClaims(details.missingOIDCClaims);
    }
    if (details.missingResourceScopes) {
      for (const [indicator, scope] of Object.entries(details.missingResourceScopes)) {
        grant.addResourceScope(indicator, scope.join(' '));
      }
    }

    grantId = await grant.save();

    const consent = {};
    if (!interactionDetails.grantId) {
      // we don't have to pass grantId to consent, we're just modifying existing one
      consent.grantId = grantId;
    }

    const result = { consent };
    return provider.interactionFinished(ctx.req, ctx.res, result, {
      mergeWithLastSubmission: true,
    });
  });

  router.get('/interaction/:uid/abort', async (ctx) => {
    const result = {
      error: 'access_denied',
      error_description: 'End-User aborted interaction',
    };

    return provider.interactionFinished(ctx.req, ctx.res, result, {
      mergeWithLastSubmission: false,
    });
  });

  return router;
};
