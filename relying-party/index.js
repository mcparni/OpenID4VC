const express = require('express')
const crypto = require('crypto')
const axios = require('axios')
const session = require('express-session')
const { v4: uuidv4 } = require('uuid');
const { sign, verify, anchor, DID, generateKeyPair, resolve } = require('@decentralized-identity/ion-tools');
const jose = require('jose');
const app = express()
const port = 3001
const cookieName = `RPOpenIDforVC`;
const os = require('os');
const fs = require('fs');
const https = require('https');
const key  = fs.readFileSync('key.pem', 'utf8');
const cert = fs.readFileSync('cert.pem', 'utf8');
const srvOptions = {
  key: key,
  cert: cert
};
process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
const networkInterfaces = os.networkInterfaces();

const URI = `https://relying-party.com:${port}`;
const OP_URI = `https://openid-provider.com:3000`;
const WALLET_URI = `https://siop-wallet.com:3002`;
const ID = "did:ion:EiBQsxvT1tz0Cz7KEfFuJhJt_134d_suJlwZ3S_bXVnoBA";
// Relying Party DID: did:ion:EiBQsxvT1tz0Cz7KEfFuJhJt_134d_suJlwZ3S_bXVnoBA
app.set('trust proxy', 1)
app.use(express.urlencoded({ extended: true }));
app.use(express.json())
app.use(session({
  genid: (req) => {
    return uuidv4()
  },
  name: cookieName,
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    maxAge: 60000 
  }
}))
const headHtml = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta http-equiv="x-ua-compatible" content="ie=edge">
    <title>Relying Party</title>
    <style>
      body {
        font-family: Arial, sans-serif;
        margin-top: 25px;
        margin-bottom: 25px;
      }
    </style>
  </head>
  <body>
    <div class="content">`;
const footHtml = `
</div>
</body>
</html>`;
function base64URLEncode(str) {
  return str.toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=/g, '');
}
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

app.get('/login', (req, res) => {
    const authzURL = `${OP_URI}/auth`;
    const clientID = `oidcCLIENT`;
    const redirectUri = `${URI}/redirect`;
    const grant = `authorization_code`;
    const scope = `openid profile`
    const rtype = `code`;
    const state = uuidv4();
    const nonce = uuidv4();
    const verifier = base64URLEncode(crypto.randomBytes(32));
    const challenge = base64URLEncode(sha256(verifier));
    req.session.verifier = verifier;
    req.session.state = state;
    req.session.nonce = nonce;
    let authz = `${authzURL}?client_id=${clientID}&redirect_uri=${redirectUri}&scope=${scope}&response_type=${rtype}&code_challenge=${challenge}&code_challenge_method=S256&state=${state}&nonce=${nonce}`;
    console.log(`Authorization request to: ${authz}`);
    console.log(`Code challenge: ${challenge}`);
    console.log(`Code verifier: ${verifier}`);
    res.redirect(authz);
});

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
    "redirect_uri": `${URI}/redirect`,
    "nonce": nonce,
    "scope": "openid",
    "state" :state,
    "presentation_definition": {
      "id": uuidv4(),
      "input_descriptors": [{
        "id": uuidv4(),
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

app.get('/walletlogin', async (req, res) => {
  console.log("wallet login")
  const authzURL = `${WALLET_URI}/authorize`;
  const state = uuidv4();
  const nonce = uuidv4();
  const requestObj = await createRequestObject(state, nonce);
  //const rtype = `vp_token`;
  const verifier = base64URLEncode(crypto.randomBytes(32));
  const challenge = base64URLEncode(sha256(verifier));
  

  req.session.verifier = verifier;
  req.session.state = state;
  req.session.nonce = nonce;

  req.session.verifier = verifier;
  let authz = `${authzURL}?request=${requestObj}&state=${state}&nonce=${nonce}`;
  console.log(`Authorization request to: ${authz}`);
  console.log(`Code challenge: ${challenge}`);
  console.log(`Code verifier: ${verifier}`);
  res.redirect(authz);
});

app.get('/', (req, res) => {
    let error = false;
    let errorMsg = ``;
    if(req.session.error) {
      error = true;
      errorMsg += `<p><b>Error: </b> ${req.session.error}</p>`;
      delete req.session.error;
      if(req.session.error_description) {
        errorMsg += `<p><b>Error Description: </b> ${req.session.error_description}</p>`;
        delete req.session.error_description;
      }
    }

    let authenticated = req.session.authenticated;
    let html = `<div style="width: auto; padding: 10px; background-color:#BF93D4; font-size: 0.6em; color: #000;">
    <h1>Relying Party -- did:ion:EiBQsxvT1tz0Cz7KEfFuJhJt_134d_suJlwZ3S_bXVnoBA</h1>
  </div>`;
    if(error) {
      html += `${errorMsg}`;
    }
    if(!authenticated) {
      html += `
    <p>Please login.</p>
    <p><button onclick='window.location.href="/login"'>Federated Login</button></p>
    <p>-- <b>or</b> --</p>
    <p><button onclick='window.location.href="/walletlogin"'>Wallet Login</button></p>`;
    } else {
      let user = req.session.user;
      console.log(user)
      let output = '';
      for (let property in user) {
        output += `${property} : ${JSON.stringify(user[property])}; <br/>`;
      }
      html += `<p><b>You:</b></p>
      <code>${"", output}</code>
      <p><b>Id token:</b></p>
      <code style="word-wrap: anywhere;">${"", req.session.idToken}</code>
      <p><button onclick='window.location.href="/logout"'>Logout</button></p>`;
    } 
    res.status(200).send(html);
})

app.get('/logout', (req, res) => {
  req.session.authenticated = false;
  if(req.session.walletAuth) {
    delete req.session.walletAuth;
    req.session.destroy((err) => {
      res.redirect("/");  
    });
  } else {
    return res.redirect(`${OP_URI}/session/end?id_token_hint=${req.session.idToken}&post_logout_redirect_uri=${URI}`);
  }
});
app.get('/error', (req, res) => {
  console.log(req.session.error)
  let statusCode = req.session.error.status;
  let description = req.session.error.message;
  let msg = req.session.error.code; 
  console.log()
  html = `<p><b>Error occured:</b></p>
  <code>
  <p> ${description} </p>
  <p> statuscode: ${statusCode} </p>
  <p> msg:${msg} </p>
  </code>
  <p><button onclick='window.location.href="/"'>Home</button></p>`;
  req.session.destroy((err) => {
    // clear cookies to force re-auth
    res.clearCookie("_session.legacy");
    res.clearCookie("_session.legacy.sig");
    res.clearCookie(cookieName);
    res.status(200).send(html);
  })
  

});
app.get('/user', (req, res) => {
  if(req.session.authenticated && !req.session.walletAuth) {
    return axios.get(`${OP_URI}/me`,{
      headers: {
        'Content-Type' : 'application/json;charset=utf-8',
        'Authorization' : "Bearer " + req.session.accessToken
      }
    })
    .then(function (response) {
      const data = response.data;
      if(data.credentialSubject) {
        req.session.user = data.credentialSubject;
      } else {
        req.session.user = data;
      }
      res.redirect("/");
    })
    .catch(function (error) {
      console.log(error);
      req.session.error = error;
      res.redirect("/error");
    });
  } if(req.session.authenticated && req.session.walletAuth) {
    req.session.user = req.session.walletAuth;
  } 
  res.redirect("/");
});

app.get('/redirect', async (req, res, next) => {
  console.log(`------------`);
  console.log("redirect_uri: ")
  console.log(req.url)
  if(req.query.error) {
    req.session.error = req.query.error;
    if(req.query.error_description)
      req.session.error_description = req.query.error_description;
    return res.redirect(`/`);
  }
  if(req.query.vp_token || req.query.id_token) {
    return next();
  }
  let ver = req.session.verifier;
  let code = req.query.code;
  let sec = Buffer.from("oidcCLIENT:233").toString('base64');
  axios.post(`${OP_URI}/token`, {
    client_id: 'oidcCLIENT',
    grant_type: 'authorization_code',
    code_verifier: ver,
    code: code,
    redirect_uri: `${URI}/redirect`
  },{
    headers: {
      'Content-Type' : 'application/x-www-form-urlencoded',
      'Authorization' : "Basic " + sec
    }
  })
  .then(async (response) => {
    req.session.accessToken = response.data.access_token;
    req.session.idToken = response.data.id_token;
    console.log(`------------`);
    console.log(`Access Token: ${req.session.accessToken}`);
    console.log(`------------`);
    console.log(`ID Token: ${req.session.idToken}`);
    console.log(`------------`);
    const idToken = response.data.id_token || undefined;
    const validIdTokenSignature = await parseJwt(idToken);
    if(!validIdTokenSignature) {
      return res.redirect(`/?error=Invalid Signature&error_description=The id token signature is invalid`);
    } else {
      req.session.authenticated = true;
      res.redirect("/user");
    }
  })
  .catch((error) => {
    //console.log(error);
    req.session.error = error;
    res.redirect("/error");
  });
});

const vcIssuerPolicies = {
  strict: true,
  trustedIssuerDID : ["did:ion:EiBAtbiEe2qtLsa5a9_fgPQDUAtxBKXLvpI6Lvpkdrcobg"]
}

const isTrustedIssuer = (iss) => {
  const strict = vcIssuerPolicies.strict;
  const trustedIssuerDID = vcIssuerPolicies.trustedIssuerDID;
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

app.get('/redirect', async (req, res) => {
  console.log("/redirect vp_token present, handling differently");
  const checkState = (req.session.state == undefined) ? false : true ;
  const idToken = req.query.id_token || undefined;
  const presentationSubmission = req.query.presentation_submission || undefined;
  const vpToken = req.query.vp_token || undefined;
  const state = req.query.state || undefined;
  const idBody = JSON.parse(Buffer.from(idToken.split(".")[1], 'base64').toString('utf8')) || undefined;
  const vpBody = JSON.parse(Buffer.from(vpToken.split(".")[1], 'base64').toString('utf8')) || undefined;
  const credential = vpBody.vp.verifiableCredential[0];
  const vcBody = JSON.parse(Buffer.from(credential.split(".")[1], 'base64').toString('utf8')) || undefined;
  const nonce = idBody.nonce;

  if(!isTrustedIssuer(vcBody.iss)) {
    return res.redirect(`/?error=Issuer Error&error_description=The Verifiable Credential is from untrusted issuer`);
  }
  try {
    // state and nonce checks
    if(nonce != vpBody.nonce && nonce != req.session.nonce) {
      return res.redirect(`/?error=Nonce Error&error_description=Nonce mismatch`);
    }
    if(checkState && (state != req.session.state)) {
      return res.redirect(`/?error=State Error&error_description=State mismatch`);
    }
  } catch(error) {
    console.log(error)
    return res.redirect(`/?error=State or Nonce Error&error_description=State or Nonce mismatch`);
  }

  
  const credentialSubject = vcBody.vc.credentialSubject;
  credentialSubject.sub = idBody.sub;
  req.session.walletAuth = credentialSubject;
  
  console.log(credentialSubject);
  req.session.idToken = idToken;
  console.log(`------------`);
  console.log(`ID Token: ${req.session.idToken}`);
  console.log(`------------`);
  req.session.authenticated = true;

  const validIdTokenSignature = await parseJwt(idToken);
  const validVpTokenSignature = await parseJwt(vpToken);
  const validCredentialSignature = await parseJwt(credential);
  
  console.log("validIdTokenSignature",validIdTokenSignature);
  console.log("validVpTokenSignature",validVpTokenSignature);
  console.log("validCredentialSignature",validCredentialSignature);
  console.log("checkstate", checkState, req.session.state);
  const walletDID = vpBody.iss;
  const validCred = isValidCredJwt(credential, walletDID);
  console.log("validCred",validCred);

  if(!validIdTokenSignature || !validVpTokenSignature || !validCredentialSignature) {
    console.log("Invalid signature");
    return res.redirect(`/?error=Signature Error&error_description=Invalid Signature`);
  }
  if(!validCred) {
    console.log("Credential Error");
    return res.redirect(`/?error=Credential Error&error_description=Invalid Credential`);
  }
  
  res.redirect("/user")
  res.status(200).send();
});



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

const getPublicKeyFromServer = async (header, body) => {
  console.log("public key from well known endpoint method")
  const keyId = header.kid;
  return axios.get(`${body.iss}/.well-known/openid-configuration`,{})
  .then(function (response) {
    return axios.get(response.data.jwks_uri,{})
    .then(function (res) {
      const keys = res.data.keys;
      const keyResult = keys.filter(key => (key.kid == keyId) || (key.kid == `#${keyId}`)).pop();
      return keyResult;
    })
    .catch(function (error) {
      console.log("error getting jwks")
      // console.log(error);
    });
  })
  .catch(function (error) {
    console.log("error getting .well-known/openid-configuration")
    //console.log(error);
  });
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
    // public key needs to be aquired from well known endpoint method
    publicJwk = await getPublicKeyFromServer(header, body);
    validSignature = await isValidSignature(header.alg, jwt, publicJwk);
    console.log("is valid signature: " + validSignature);
    return validSignature;
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

const server = https.createServer(srvOptions, app);
server.listen(port, () => {
  console.log(`Client app listening on port: ${port}`);
})