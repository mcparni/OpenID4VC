const express = require('express')
const crypto = require('crypto')
const axios = require('axios')
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const nodeJose = require('node-jose')
const jose = require('jose');
const { sign, verify, anchor, DID, generateKeyPair, resolve } = require('@decentralized-identity/ion-tools');
const fs = require('fs');
const https = require('https');
const  { JsonDB, Config } = require('node-json-db')
const key  = fs.readFileSync('key.pem', 'utf8');
const cert = fs.readFileSync('cert.pem', 'utf8');
const srvOptions = {
  key: key,
  cert: cert
};

const app = express()
const PORT = 3002;
const URI = `https://siop-wallet.com:${PORT}`;

const cookieName = `WalletOpenIDforVC`;
const os = require('os');
const networkInterfaces = os.networkInterfaces();

const ID = "did:ion:EiAZF8EUsRKvkuqQeAvtha8WnxFa2VlK3M7XwJ1EsOfEvA";
// Wallet DID: did:ion:EiAZF8EUsRKvkuqQeAvtha8WnxFa2VlK3M7XwJ1EsOfEvA

let db = new JsonDB(new Config("Database", true, true, '/'));
app.set('trust proxy', 1)
app.use(express.urlencoded({ extended: true }));
app.use(express.json())
app.use(session({
  genid: (req) => {
    return uuidv4()
  },
  name: cookieName,
  secret: 'keyboard elephant',
  resave: false,
  saveUninitialized: true,
  cookie: { 
    maxAge: 60000 
  }
}))

function base64URLEncode(str) {
  return str.toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=/g, '');
}
function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
}

app.get('/.well-known/openid-configuration', (req, res) => {
  console.log("/.well-known/openid-configuration")
  let metadata = {
    "issuer": `${URI}`,
    "authorization_endpoint": `${URI}/authorize`,
    "subject_types_supported": [
      "pairwise"
    ],
    "id_token_signing_alg_values_supported": [
      "ES256K"
    ],
    "request_object_signing_alg_values_supported": [
      "ES256K"
    ],
    "subject_syntax_types_supported": [
      "did:ion"
    ],
    "id_token_types_supported": [
      "subject_signed_id_token"
    ],
    "scopes_supported":
      ["openid"],
    "response_types_supported":
      ["id_token", "id_token vp_token", "vp_token"],
    "vp_formats_supported": {
      "jwt_vc_json": {
        "alg_values_supported": [
          "ES256K"
        ]
      },
      "jwt_vp_json": {
        "alg_values_supported": [
          "ES256K"
        ]
      }
    }
  }
  res.set('Content-Type', 'application/jwk-set+json; charset=utf-8');
  res.status(200).send(metadata);
});


const isValidRequest = (req, body) => {
  const sub = body.client_id || undefined;
  const redirectUri = body.redirect_uri || undefined;
  const validDate = isValidDate(body);
  let responseType = body.response_type || undefined;
  const scope = body.scope || undefined;
  const nonce = body.nonce || undefined;
  const presentationDefinition = body.presentation_definition || undefined;
  // optional
  const state = body.state || undefined;

  if(sub == undefined || redirectUri == undefined ||
  responseType == undefined || scope == undefined || nonce == undefined
  || presentationDefinition == undefined ) {
    // required parameters missing
    console.log("required parameters missing");
    return false;
  }
  responseType = responseType.replaceAll("%20"," "); 
  const responses = responseType.split(" ");
  // should add the redirect uri validation from DID document service?
  if(sub != body.iss && (!responses.includes("id_token") || !responses.includes("vp_token")) &&
  scope != "openid" || !validDate) {
    // invalid values for parameters
    console.log("invalid values for parameters")
    return false;
  }
  req.session.redirectUri = redirectUri;
  req.session.nonce = nonce;
  req.session.requestAud = sub;
  req.session.responses = responses;
  req.session.presentationDefinition = presentationDefinition;
  if(state) {
    req.session.state = state;
  }
  return true;
}

// There might exist many parameters in the request,
// only the {request} object is important here.
app.get('/authorize', async (req, res) => {
  
  const requestObj = req.query.request || undefined;
  if(requestObj) {
    const body = JSON.parse(Buffer.from(requestObj.split(".")[1], 'base64').toString('utf8')) || undefined;
    const validRequestSignature = await parseJwt(requestObj);
    const validRequest = isValidRequest(req, body)
    if(validRequestSignature && validRequest) {
      console.log("validRequestSignature: " + validRequestSignature);
      console.log("validRequest: " + validRequest);
      console.log(req.session);
      res.redirect("/consent");
    } else {
      res.status(400).send();    
    }
  } else {
    res.status(400).send();  
  }
});

const validClientId = (clientId) => {
  let valid = true;
  return valid;
};
app.get('/jwks', async  (req, res) => {
    console.log("/jwks")
    const ks = fs.readFileSync('keys.json')
    const keyStore = await nodeJose.JWK.asKeyStore(ks.toString())
    res.set('Content-Type', 'application/jwk-set+json; charset=utf-8');
    res.status(200).send(keyStore.toJSON());
});

const listCredentials = (credentials) => {
  let html = `
  <script>
    function removeCredential(credentialId) {
      if(confirm("Remove this credential?")) {
        fetch('credential/' + credentialId, {
          method: 'DELETE',
        })
        .then(res => {
          window.location.href = "/";
        })
      }
    }
  </script>
  `;
  if(credentials.length > 0) {
    for (let i = 0; i < credentials.length; i++) {
      html += `<div style="font-weight: normal; border: 1px solid #e1e1e1; padding: 10px; margin: 5px 0;">`;
      let date = new Date(credentials[i].iat * 1000).toISOString();
      html += `<p><b>Issuer: </b>${credentials[i].issuer}</p>`;
      html += `<p><b>Issued at: </b>${date}</p>`;
      html += `<p><b>Type: </b>`;
      let type = ``; 
      for(let j = 0; j < credentials[i].type.length; j++) {
        if( credentials[i].type[j] != 'VerifiableCredential') {
          type += `${credentials[i].type[j]}, `;
        }
      }
      type = type.substring(0,type.length -2);
      html += `${type}</p>`;
      html += `<p><b>Content: </b>`;
      let credentialContent = ``;
      for (const [key, value] of Object.entries(credentials[i].credentialSubject)) {
        credentialContent += `<b>${key}</b>: ${value}, `;
      }
      credentialContent = credentialContent.substring(0,credentialContent.length -2);
      html += `${credentialContent}</p>`;
      html += `<button onclick="removeCredential('${credentials[i].id}')">Remove</button>`
      html += `</div>`;
    }
    
  } else {
    html += `<p>No credentials. <a href="/import">Import</a>.</p>`;
  }
  return html;
};

const getNavigation = () => {
  const html = `<div style="width: auto; padding: 10px; background-color:#61C6CE; font-size: 0.6em; color: #000;">
  <h1>SIOP Wallet -- did:ion:EiAZF8EUsRKvkuqQeAvtha8WnxFa2VlK3M7XwJ1EsOfEvA</h1>
  </div>
  <div>
    <ul style="list-style: none;margin-left: 0;padding-left: 0;">
      <li style="display: inline;padding-right: 10px;"><a href="/">Credentials</a></li>
      <li style="display: inline;padding-right: 10px;"><a href="/import">Import</a></li>
      <li style="display: inline;"><a href="/connections">Connections</a></li>
    </ul>
  </div>`;
  return html;
};

app.delete('/credential/:id', async (req, res) => {
  const data = await db.getData("/");
  const id = req.path.split("/")[1];
  let index = -1;
  for(let i = 0; i < data.credentials.length; i++) {
    if(data.credentials[i].id = id) {
      index = i;
    }
  }
  if(index != -1) {
    await db.delete(`/credentials[${index}]`);
  } else {
    console.log("credential does not exist");
  }
  res.status(204).send();
});

app.delete('/connection/:id', async (req, res) => {
  const data = await db.getData("/");
  const id = req.path.split("/")[1];
  let index = -1;
  for(let i = 0; i < data.connections.length; i++) {
    if(data.connections[i].id = id) {
      index = i;
    }
  }
  if(index != -1) {
    await db.delete(`/connections[${index}]`);
  } else {
    console.log("connection does not exist");
  }
  res.status(204).send();
});

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


const isValidCredJwt = (jwt) =>  {
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
  if(body.sub != ID ) {
    console.log("the subject in token does not match the wallet DID");
    return false;
  }
  console.log("Valid DID JWT")
  return true;
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

const saveVC =  async (jwt) => {
  const body = JSON.parse(Buffer.from(jwt.split(".")[1], 'base64').toString('utf8'));
  const credential = {
    "id": uuidv4(),
    "issuer": body.iss,
    "iat": body.iat,
    "type": body.vc.type,
    "credentialSubject": body.vc.credentialSubject,
    "jwt": jwt
  };
  await db.push("/", {credentials: [credential]}, false);
};

const matchCredentialType = (vc, type) => {
  let match = true;
  for(let i = 0; i < type.length; i++) {
    if(!vc.type.includes(type[i])) {
      match = false;
    }
  }
  return match;
};

const isUniqueVC = async (iss, vc) => {
  let unique = true;
  let data = await db.getData("/");
  if(!data.credentials) {
    return unique;
  }
  const issuers = data.credentials.filter(credential => credential.issuer == iss);
  if(issuers.length > 0) {
    for(let i = 0; i < issuers.length; i++) {
      if(matchCredentialType(vc, issuers[i].type)) {
        unique = false;
      }
    }
  } else {
    unique =  true;
  }
  return unique;
};

app.post('/import', async (req, res) => {
  const jwt = req.body.jwt || undefined;
  if(jwt) {
    // validate and parse
    const validJWT = await parseJwt(jwt);
    const validCredJwt =  isValidCredJwt(jwt);
    if(validJWT && validCredJwt) {

      const body = JSON.parse(Buffer.from(jwt.split(".")[1], 'base64').toString('utf8'));
      const vc = body.vc;
      const iss = body.iss;
      if(await isUniqueVC(iss, vc)) {
        console.log("is unique VC")
        saveVC(jwt);
        res.status(201).send();
      } else {
        console.log("same type of credential is found from same issuer");
        res.status(409).send();
      }
    } else {
      console.log("invalid jwt")
      res.status(400).send();
    }
  }
  res.status(400).send();
});

app.get('/import', async (req, res) => {
  let data = await db.getData("/");
  let html = getNavigation();
  html += `
  <script>
    function manualImport() {
      var credential = document.getElementById("cred").value;
      fetch('/import', {
        method: 'POST',
        headers: {
          "Content-Type": "application/json"
        },
        body:JSON.stringify({"jwt":credential})
      }).then(response => {
        //response.json()
        if(response.ok == true && response.status == 201) {
          window.location.href="/";
        }
        if(response.status == 409) {
          alert("Same type of Credential from same Issuer already found.");
        }
        if(response.status == 400) {
          alert("JWT error");
        }
      })
    }
  </script>
  <p><b>Import Credential:</b></p>`;
  if(!data.credentials) {
    res.status(200).send(html);
  }
  html += `<textarea id="cred" style="width: 75%; height: 150px;"></textarea><br />
  <button onclick="manualImport();">Manual Import</button>`;
  res.status(200).send(html);
})

const isConnection = async (did) => {
  let connected = true;
  let data = await db.getData("/");
  if(!data.connections) {
    return connected;
  }
  const connections = data.connections.filter(connection => connection.did == did);
  if(connections.length > 0) {
    for(let i = 0; i < connections.length; i++) {
      if(did == connections[i].did) {
        connected = true;
      }
    }
  } else {
    connected =  false;
  }
  return connected;
};



const saveConnection =  async (connectionDID) => {
  const connection = {
    "id": uuidv4(),
    "date": getDateEpoch(),
    "did":connectionDID
  };
  if(!await isConnection(connectionDID)) {
    console.log("Saving as trusted connection");
    await db.push("/", {connections: [connection]}, false);
  }
};

const listConnections = (connections) => {
  let html = `
  <script>
    function removeConnection(connectionId) {
      if(confirm("Remove this trusted connection?")) {
        fetch('connection/' + connectionId, {
          method: 'DELETE',
        })
        .then(res => {
          window.location.href = "/connections";
        })
      }
    }
  </script>`;
  if(connections.length > 0) {
    for (let i = 0; i < connections.length; i++) {
      html += `<div style="font-weight: normal; border: 1px solid #e1e1e1; padding: 10px; margin: 5px 0;">`;
      let date = new Date(connections[i].date * 1000).toISOString();
      html += `<p><b>Connection DID: </b>${connections[i].did}</p>`;
      html += `<p><b>Connected at: </b>${date}</p>`;
      html += `<button onclick="removeConnection('${connections[i].id}')">Remove</button>`
      html += `</div>`;
    } 
  } else {
    html += `<p>No trusted connections.</p>`;
  }
  return html;
};

/*
  Query requested credentials from Wallet
*/
const queryCredentials = async (credentials) => {
  let data = await db.getData("/");
  let found = [];
  for (let i = 0; i < data.credentials.length; i++) {
    for(j = 0; j < credentials.length; j++) {
      if(matchCredentialType(data.credentials[i], credentials[j])) {
        found.push(data.credentials[i]);
      }
    }
  }
  console.log(`found : ${found}`)
  return found;
};

const createPresentationSubmission = () => {
  return {
    "definition_id": uuidv4(),
    "id": uuidv4(),
    "descriptor_map": [{
      "id": "id_credential",
      "path": "$",
      "format": "jwt_vp_json",
      "path_nested": {
        "path": "$.vp.verifiableCredential[0]",
        "format": "jwt_vc_json"
      }
    }]
  };
};

const createPresentationToken = async (req, credential) => {
  const privateJwk  = JSON.parse(fs.readFileSync('did-private.json', 'utf8'));
  const alg = "ES256K";
  const iat = getDateEpoch();
  const header = {
    "kid": `${ID}#key-1`,
    "alg": alg,
    "typ":"vp+jwt"
  }
  const body = {
    "iss": ID,
    "nbf": iat,
    "iat": iat,
    "jti": `${ID}-${uuidv4()}`,
    "nonce": req.session.nonce || undefined,
    "vp": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
      ],
      "type": ["VerifiablePresentation"],
      "verifiableCredential": []
    }
  }
  for(let i = 0; i < credential.length; i++) {
    body.vp.verifiableCredential.push(credential[i].jwt);
  }
  const jws = await sign({ header: header, payload: body, privateJwk }); 
  return jws;
}


const createIdToken = async (req) => {
  const privateJwk  = JSON.parse(fs.readFileSync('did-private.json', 'utf8'));
  const alg = "ES256K";
  const iat = getDateEpoch();
  const header = {
    "kid": `${ID}#key-1`,
    "alg": alg,
    "typ":"JWT"
  }
  const body = {
    "iss": ID,
    "sub": ID,
    "aud": req.session.requestAud || undefined,
    "nonce": req.session.nonce || undefined,
    "nbf": iat,
    "iat": iat,
    "exp": iat + 3600,
    "jti": `${uuidv4()}`
  }
  const jws = await sign({ header: header, payload: body, privateJwk }); 
  return jws;
};

const createResponseVP = async (req, credentials) => {
  console.log("Create Verifiable Presentation Response ");
  const idToken =  await createIdToken(req);
  const presentationSubmisssion = JSON.stringify(createPresentationSubmission());
  const vpToken =  await createPresentationToken(req, credentials);
  return `?id_token=${idToken}&presentation_submission=${presentationSubmisssion}&vp_token=${vpToken}`;
}

app.get('/approve', async (req, res) => {
  console.log("approve");
  const credentials = req.session.credentials;
  if(credentials) {
    // wrap in to verifiable presentation
    // TODO: implement real session state check
    let responseParams = await createResponseVP(req, credentials);
    if(req.session.state) {
      responseParams += `&state=${req.session.state}`;
    }
    // return to requester redirect URI (value from req.session)
    console.log(responseParams);
    saveConnection(req.session.requestAud);
    res.redirect(`${req.session.redirectUri}${responseParams}`);
    //res.status(200).send();
  } else {
    res.status(400).send();
  }
  

});

app.get('/reject', async (req, res) => {
  res.redirect(`${req.session.redirectUri}/?error=rejected&error_description=Wallet rejected the presentation request`);
});



app.get('/consent', async (req, res, next) => {
  console.log("definitions");
  try {
    const definition = req.session.presentationDefinition;
    console.log(definition);
    const descLength = definition.input_descriptors.length;
    let constraints = [];
    let required = [];
    for(let i = 0; i < descLength; i++) {
      constraints.push(definition.input_descriptors[i].constraints);
    }

    for(let j = 0; j < constraints.length; j++) {
      for(let e = 0; e < constraints[j].fields.length; e++) {
        let details = {};
        details.type = [];
        details.path = constraints[j].fields[e].path.pop();
        details.type.push(constraints[j].fields[e].filter.pattern);
        details.type.push("VerifiableCredential");
        required.push(details);
      }
    }

    found = await queryCredentials(required);
    if(found.length == 0) {
      return res.redirect(`${req.session.redirectUri}/?error=credential_error&error_description=No credentials in wallet`);
    }
    req.required = found;
    return next();
  } catch(error) {
    return res.redirect(`${req.session.redirectUri}/?error=credential_error&error_description=Error with credentials`);
  }
  
});

app.get('/consent', async (req, res) => {
  let html = getNavigation();
  const required = req.required;
  req.session.credentials = required;
  let text = `The OP requires your credential(s): `;
  for(let i = 0; i  < required.length; i++) {
    for(let j = 0; j < required[i].type.length; j++) {
      if(required[i].type[j] != 'VerifiableCredential') {
        text += `${required[i].type[j]} `;
      }
    }
    text += ` with data `;
    for (const [key, value] of Object.entries(required[i].credentialSubject)) {
      text += `${key}: ${value}, `;
    }
  }
  text += `Do you approve?`
  html += `
  <script>
  document.body.addEventListener("load", consent());
  function consent() {
    if(confirm("`;
  html += `${text}")) {
      window.location.href = "/approve";
    } else {
      window.location.href = "/reject";
    }
  }
  </script>`;
  res.status(200).send(html);
});

app.get('/connections', async (req, res) => {
  let data = await db.getData("/");
  let html = getNavigation();
  html += `<p><b>Trusted Connections</b> (Relying Parties, OpenID Providers, etc ...):</p>`;
  if(!data.connections) {
    res.status(200).send(html);
  }
  const connections = data.connections.filter(connection => connection.id);
  let connectionsHtml = listConnections(connections);
  html += connectionsHtml;
  
  res.status(200).send(html);
})

app.get('/', async (req, res) => {
    let data = await db.getData("/");
    let html = getNavigation();
    html += `<p><b>Verifiable Credentials:</b></p>`;
    if(!data.credentials) {
      res.status(200).send(html);
    }
    const credentials = data.credentials.filter(credential => credential.id);
    let credentialsHtml = listCredentials(credentials);
    html += credentialsHtml;
    res.status(200).send(html);
    
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

const server = https.createServer(srvOptions, app);
server.listen(PORT, () => {
  console.log(`Client app listening on port: ${PORT}`);
})