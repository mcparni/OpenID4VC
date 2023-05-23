# OpenID4VC
This repository contains OpenID4VC project files. The OpenID4VC is the technical part of feasibility study covered in "On Self-Sovereign Identity: Verifiable Credentials and Presentations with OpenID Connect" by Miika Pärni. It is a Master’s thesis for Master’s Programme in Computer Science of University of Helsinki.   
The OpenID4VC is a system which enriches OpenID Connect with Verifiable Credentials and Verifiable Presentations. the OpenID4VC contains four main components: OpenID Provider, Issuer, Wallet and Relying Party (optional: Relying Party2 for testing the Single Sign-On). User is able to log in to Relying Party using federated login through OpenID Provider and the Wallet (using the new Federated Verifiable Credentials Flow) or directly with the Wallet (using the new Verifiable Credentials Flow). The Issuer is able to issue Verifiable Credentials, ``IDCardCredential``, which can be imported to Wallet. This Credential can be used to login to Relying Party.  All the components utilise ``did:ion`` as their Decentralized Identifier Method. Also all of the components utilise the [ION Tools](https://github.com/decentralized-identity/ion-tools) to enable the use of ``did:ion`` method and interact with its Verifiable Data Registry.
The OpenID4VC contains self-signed certificates for all of the components. There are also private keys included which can be used for signing JWT. The decision to include the private keys has been done on purpose.  
**NOTE!**  It is recommended that none of components, keys or certificates should be used in production, or similar type of environment. It is better to test these locally.
## Prerequisites
 * NodeJS >= v.18.10.0
 * npm >= 8.19.2
 * Git client
 * Edit /etc/hosts (Windows: c:\Windows\System32\Drivers\etc\hosts):  
 ```
 127.0.0.1  relying-party.com, openid-provider.com, siop-wallet.com, credential-issuer.com
 # optional:
 127.0.0.1 relying-party2.com
 ```

## Instructions
**Install:**  
 ```
 git clone https://github.com/mcparni/OpenID4VC.git
 cd OpenID4VC
 cd issuer
 npm install
 cd ..
 cd node-oidc-provider
 npm install
 cd ..
 cd relying-party
 npm install
 cd ..
 cd wallet
 npm install
 cd ..
 ```
**Optional (for Relying Party2):**  
 ```
 cd rp2
 npm install
 cd ..
 ```
**Run:**  
Open four separate tabs or windows in the terminal. Each of the tab or window will run their own component, e.g., tab1 runs issuer, tab2 runs wallet, ...   
Make sure you are in the the root of the cloned directory for each tab, /OpenID4VC. All the components have self-signed certificates, so the browser warning needs to be ignored and the exception to connect should be allowed in these cases.    

**tab1:** 
```
cd issuer
node index.js
```
The Issuer is now running in: ``https://credential-issuer.com:3003``  
    

**tab2:** 
```
cd wallet
node index.js
```
The Wallet is now running in: ``https://siop-wallet.com:3002``   

**tab3:** 
```
cd node-oidc-provider
node example/standalone.js
```
The OpenID Provider is now running in: ``https://openid-provider.com:3000``    

**tab4:** 
```
cd relying-party
node index.js
```
The Relying Party is now running in: ``https://relying-party.com:3001``      

Optional (for Relying Party2) **tab5**  :

```
cd rp2
node index.js
```
The Relying Party is now running in: ``https://relying-party2.com:3005``     
  

**The Use Of Components**   
1. Create a Verifiable Credential in the Issuer. The values can be set freely, except the last input field, the Subject DID (Wallet DID). This must be the DID of the Wallet (did:ion:EiAZF8EUsRKvkuqQeAvtha8WnxFa2VlK3M7XwJ1EsOfEvA), the Wallet rejects the Credential if it has not been issued to it. 
2. Copy the created credential (JWT format in the text area)
3. Go to Wallet Application and Import the credential. Note, the Wallet will not allow to import same credential from same issuer twice.
4. Go to Relying Party and try different methods of login (Federated Login or Wallet login)
5. When using federated login, there are two options:   
       * Username and password, the normal login.   
       * Sign in with Wallet, the method produced for the OpenID4VC. 
    
**Exit Program(s)**   
Press CTRL-C on each tab which runs program.  

## Components
Following components are included in the OpenID4VC

### Relying Party
This is an application where user logs in. The User can use federated login and also login directly with the wallet. Is configured to trust Verifiable Credentials granted by the Issuer. The Relying Party has an OpenID Connect Client configured in the OpenID Provider.  
DID: did:ion:EiBQsxvT1tz0Cz7KEfFuJhJt_134d_suJlwZ3S_bXVnoBA

### Issuer
The issuer of Verifiable Credentials of type ``IDCardCredential``.  Requires four attributes, ``Given Name``, ``Family Name``, ``Date Of Birth`` and ``Subject DID``. The ``Subject DID`` must be the Wallet's DID.    
DID: did:ion:EiBAtbiEe2qtLsa5a9_fgPQDUAtxBKXLvpI6Lvpkdrcobg. 

### Wallet
The Wallet can import and store Verifiable Credentials and also approve Verifiable Presentation requests from OpenID Provider and the Relying Party (also from Relying Party2). The Verifiable Credentials can also be deleted from the Wallet.
DI: did:ion:EiAZF8EUsRKvkuqQeAvtha8WnxFa2VlK3M7XwJ1EsOfEvA

### OpenID Provider
This is forked from [panva/node-oidc-provider](https://github.com/panva/node-oidc-provider) and modified to resolve DIDs, get the public keys from DID Documents and use the Wallet as a federated login option.   
DID: did:ion:EiBr3cl0yOq4TDkQ-AioibD8NF2Miml3BQ-40smk5Viu0Q

### Relying Party2
This is like Relying Party. The only purpose is that if the Single Sign-On needs to be tested. The Relying Party2 has also an OpenID Connect Client configured in the OpenID Provider.   
DID: did:ion:EiBQsxvT1tz0Cz7KEfFuJhJt_134d_suJlwZ3S_bXVnoBA

## Extra information

All of the (self-signed) certificates and their keys have been created with following command (non-interactive and 10 years expiration):
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=FI/ST=Uusimaa/L=Helsinki/O=TheCompany/OU=ComputerScienceProjects/CN=example.com"
```
If new DIDs should be created, they can be created with following method:
```
const { sign, verify, anchor, DID, generateKeyPair, resolve } = require('@decentralized-identity/ion-tools');
const fs = require('fs')
const { writeFile }  = require('fs/promises');

const anchorDID = async () => {
  let authnKeys = await generateKeyPair();
  let did = new DID({
    content: {
      publicKeys: [
        {
          id: 'key-1',
          type: 'EcdsaSecp256k1VerificationKey2019',
          publicKeyJwk: authnKeys.publicJwk,
          purposes: [ 'authentication','assertionMethod', 'capabilityInvocation', 'capabilityDelegation' ]
        }
      ],
      services: [
        {
          id: 'domain-1',
          type: 'LinkedDomains',
          serviceEndpoint: 'https://example.com:3008'
        }
      ]
    }
  });

  let longFormDID = await did.getURI();
  let shortFormDID = await did.getURI('short');
  
  // get keys for modify and recover
  let ionOps = await did.getAllOperations();

  let createRequest = await did.generateRequest();
  let anchorResponse = await anchor(createRequest);

  console.log(anchorResponse);
  // store the DIDs (short and long) to a file
  await writeFile('./did-info.json', JSON.stringify({"short":shortFormDID,"long":longFormDID}));
  // store the keys for modify and recover to a file
  await writeFile('./ion-did-ops-v1.json', JSON.stringify({ ops: ionOps }));
  // store the private key to a file
  await writeFile('./did-private.json', JSON.stringify(authnKeys.privateJwk));
  // store the public key to a file
  await writeFile('./did-public.json', JSON.stringify(authnKeys.publicJwk));
};
```

## Author
Miika Pärni  
2023
## License
MIT
