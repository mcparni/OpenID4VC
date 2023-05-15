const express = require('express')
const crypto = require('crypto')
const axios = require('axios')
const session = require('express-session')
const { v4: uuidv4 } = require('uuid');
const app = express()
const port = 3003
const jose = require('jose')
const cookieName = `IssuerOpenIDforVC`;
const { sign, verify, anchor, DID, generateKeyPair, resolve } = require('@decentralized-identity/ion-tools');
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
const ID = "did:ion:EiBAtbiEe2qtLsa5a9_fgPQDUAtxBKXLvpI6Lvpkdrcobg";
// Issuer DID: did:ion:EiBAtbiEe2qtLsa5a9_fgPQDUAtxBKXLvpI6Lvpkdrcobg


app.set('trust proxy', 1)
app.use(express.urlencoded({ extended: true }));
app.use(express.json())
app.use(session({
  genid: (req) => {
    return uuidv4()
  },
  name: cookieName,
  secret: 'keyboard zebra',
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

const getDateUTC = () => {
  var date = new Date();
  var now_utc = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(),
                  date.getUTCDate(), date.getUTCHours(),
                  date.getUTCMinutes(), date.getUTCSeconds());
  console.log(new Date(now_utc));
  console.log(date.toISOString());
  return date.toISOString();
}

const getDateEpoch = () => {
  const now = new Date()  
  const utcMilllisecondsSinceEpoch = now.getTime() + (now.getTimezoneOffset() * 60 * 1000)  
  const utcSecondsSinceEpoch = Math.round(utcMilllisecondsSinceEpoch / 1000)  
  return utcSecondsSinceEpoch;
};

const createCredential = async (credentialObj) => {
  const privateJwk  = JSON.parse(fs.readFileSync('did-private.json', 'utf8'));
  const alg = "ES256K";
  const iat = getDateEpoch();
  const header = {
    "kid": `${ID}#key-1`,
    "alg": alg,
    "typ":"vc+jwt"
  }
  const body = {
    "iss": ID,
    "nbf": iat,
    "iat": iat,
    "jti": `${ID}-${uuidv4()}`,
    "sub": credentialObj.subDID,
    "vc": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "type": [
        "VerifiableCredential",
        "IDCardCredential"
      ],
      "credentialSubject": {
        "given_name": credentialObj.givenName,
        "family_name": credentialObj.familyName,
        "date_of_birth": credentialObj.dateOfBirth
      }
    }
  }
  const jws = await sign({ header: header, payload: body, privateJwk });
  console.log("Signed JWS:", jws)
  return jws;
}

/*
  Does not require bearer token now
*/
app.post('/credential', async (req, res) => {
  const givenName = req.body.given_name;
  const familyName = req.body.family_name;
  const dateOfBirth = req.body.date_of_birth;
  const subDID = req.body.sub_did;

  if(givenName && familyName && subDID) {
    const credentialObj = {
      "givenName":givenName,
      "familyName":familyName,
      "dateOfBirth":dateOfBirth,
      "subDID":subDID
    }
    const credential = await createCredential(credentialObj);
    res.status(200).send(JSON.stringify({"vc_jwt":credential}));
  } else {
    res.status(400).send();
  }
});

const isValidSignature = async (alg, jwt, publicJwk) => {
  const publicKey = await jose.importJWK(publicJwk, alg);
  let verSig = undefined;
  let isValid = false;
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


app.post('/cred', async (req, res) => {
  const credentialJWT = await createCredential(req.body.cred) 
  console.log(req.body.cred)
  res.redirect(`/?export=${credentialJWT}`);
});

app.get('/', (req, res) => {
    const exp = req.query.export;
    let cred = ``;
    if(exp) {
      cred = `<textarea id="cred" style="width: 75%; height: 150px;">${exp}</textarea>`;
    }
    
    console.log(exp)
    let authenticated = req.session.authenticated;
    let html = ``;
    if(!authenticated) {
      html = `
      <div style="width: auto; padding: 10px; background-color:#F08E81; font-size: 0.6em; color: #000;">
                <h1>Credential Issuer -- did:ion:EiBAtbiEe2qtLsa5a9_fgPQDUAtxBKXLvpI6Lvpkdrcobg</h1>
              </div>
              <p>Fill in the credential details for IDCardCredential:</p>
                <form action="/cred" method="post">
                <input type="text" id="givenName" style="min-width: 420px;" name="cred[givenName]" placeholder="Given Name" required /><br />
                <input type="text" id="familyName" style="min-width: 420px;" name="cred[familyName]" placeholder="Family Name" required /><br />
                <input type="text" id="dateOfBirth" style="min-width: 420px;" name="cred[dateOfBirth]" placeholder="Date of Birth (DD-MM-YYYY)" required /><br />
                <input type="text" id="subDID" style="min-width: 420px;" name="cred[subDID]" placeholder="Subject DID (Wallet DID) " required /><br />
                <input type="submit" value="create" />
                </form>
              `;
              if(exp) {
                html += `<p>Verifiable Credential:</p>${cred}<br /><button onclick="copyText();">Copy to Clipboard</button>
                <a href="https://jwt.io/" target="_blank">JWT.io</a>
                <script>
                function copyText() {
                  var copyText = document.getElementById("cred");
                  copyText.select();
                  copyText.setSelectionRange(0, 99999);
                  navigator.clipboard.writeText(copyText.value);
                }
                </script>`;
              }
    } else {
      let user = req.session.user;
      let output = '';
      for (let property in user) {
        output += `${property} : ${user[property]}; <br/>`;
      }
      html = `<p><b>You:</b></p>
      <code>${"", output}</code>
      <p><b>Id token:</b></p>
      <code>${"", req.session.idToken}</code>
      <p><button onclick='window.location.href="/logout"'>Logout</button></p>`;
    } 
    res.status(200).send(html);
})

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
  }
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

const parseJwt = async (jwt) => {
  const header = JSON.parse(Buffer.from(jwt.split(".")[0], 'base64').toString('utf8'));
  const body = JSON.parse(Buffer.from(jwt.split(".")[1], 'base64').toString('utf8'));
  const keyId = header.kid;
  let doc = undefined;
  let publicJwk;
  let validSignature = false;
  if(keyId.indexOf("did:") >= 0) {
    // public key needs to be aquired from did document
    const did = header.kid.split("#")[0];
    const keyId = `#${header.kid.split("#")[1]}`;
    doc = await resolve(did);
    publicJwk = getPublicKeyFromDocument(doc, keyId);
    validSignature = await isValidSignature(header.alg, jwt, publicJwk);
    console.log("is valid signature: " + validSignature);
  } else {
    // public key needs to be aquired from well known endpoint method
    publicJwk = await getPublicKeyFromServer(header, body);
    validSignature = await isValidSignature(header.alg, jwt, publicJwk);
    console.log("is valid signature: " + validSignature);
  }
};


const server = https.createServer(srvOptions, app);
server.listen(port, () => {
  console.log(`Client app listening on port: ${port}`);  
})