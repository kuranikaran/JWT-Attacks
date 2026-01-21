# 🔐 JWT Attacks Playbook 

<img width="2048" height="1324" alt="image" src="https://github.com/user-attachments/assets/7a3ebdc7-4398-460c-bbed-8101ab4be41e" />


### A practical guide to breaking JSON Web Token authentication

> This repository documents real-world **JWT authentication bypass techniques** caused by insecure implementation choices.
>  
> Each attack is explained with **root cause, exploitation logic, impact, and mitigation**.
>  
> JWTs are not insecure by design  **misuse makes them vulnerable**.

---

## 📌 Scope

This repository covers the following JWT attack classes:

- Unverified signature acceptance
- Flawed signature verification
- Weak HMAC signing keys
- JWK header injection
- JKU header injection
- `kid` header path traversal
- Algorithm confusion (RS256 ↔ HS256)
- Algorithm confusion with no exposed key

> All techniques were validated in hands-on security labs that closely resemble real-world API misconfigurations.

---

## 📚 Table of Contents

- [JWT Basics](#jwt-basics)
- [Attack Surface Overview](#attack-surface-overview)
- [JWT Authentication Bypass Techniques](#jwt-authentication-bypass-techniques)
  - [Unverified Signature](#1-unverified-signature)
  - [Flawed Signature Verification](#2-flawed-signature-verification)
  - [Weak Signing Key](#3-weak-signing-key)
  - [JWK Header Injection](#4-jwk-header-injection)
  - [JKU Header Injection](#5-jku-header-injection)
  - [KID Header Path Traversal](#6-kid-header-path-traversal)
  - [Algorithm Confusion](#7-algorithm-confusion-rs256--hs256)
  - [Algorithm Confusion (No Exposed Key)](#8-algorithm-confusion-with-no-exposed-key)
- [Common Root Causes](#common-root-causes)
- [Defensive Checklist](#defensive-checklist)

---

## 🔍 JWT Basics

A JSON Web Token (JWT) consists of three Base64URL-encoded components:

HEADER.PAYLOAD.SIGNATURE


JWT security **does not rely on encryption**, but on **correct signature verification and strict validation logic**.

> ❗ Any JWT field controlled by the client must be treated as **untrusted input**.

---

## 🎯 Attack Surface Overview

JWT vulnerabilities typically target:

- Signature verification logic
- Algorithm handling (`alg`)
- Key management (`kid`, secrets, public keys)
- Header trust (`jwk`, `jku`)
- Claim validation (`exp`, `aud`, `iss`)

> Most JWT vulnerabilities arise from **developer convenience shortcuts**, not cryptographic failures.

---

## 🧨 JWT Authentication Bypass Techniques

---

### 1️⃣ Unverified Signature

**What breaks**  
The server decodes JWTs but never verifies the signature.

**Why it happens**
- `decode()` used instead of `verify()`
- Misconfigured authentication middleware

**Exploitation logic**
- Modify payload claims (e.g., `"role": "admin"`)
- Keep signature invalid or empty
- Server still accepts the token

**Impact**
- Privilege escalation
- Account takeover

**Mitigation**
- Always enforce signature verification
- Explicitly reject unsigned tokens

---
### 1️⃣ Unverified Signature Attack Example

- Modify the JWT token signature's last bits and resend the request if it returns 200 OK it's Vulnerable
- For example change pg to xx or ab in serialized jwt section

<img width="534" height="628" alt="Screenshot 2025-12-18 at 9 31 00 PM" src="https://github.com/user-attachments/assets/50ca75fc-db07-4933-9fdc-ecdfd349e350" />

- Decoding is not Verification
- Here Kid param is the key needs to be used 
- Here iss is issuer of jwt token
- Here exp is expiry in epoch time
- Here sub is account user we are logged with

---

### 2️⃣ Flawed Signature Verification

**What breaks**  
Signature verification exists but fails open due to improper error handling.

**Common mistakes**
- Verification exceptions ignored
- Failure defaults to authenticated state

**Impact**
- Authentication bypass

**Mitigation**
- Fail closed on all verification errors
- Log and monitor verification failures

---

### 2️⃣ Flawed Signature Verification Attack Example

- Modify and check if the application accepts an unsigned jwt / none algorithm
- Change the algorithm param to none and remove the signature from the serialized jwt section and resend the request if it returns 200 OK it's Vulnerable
  
  <img width="650" height="650" alt="Request" src="https://github.com/user-attachments/assets/f2413a55-2ce8-443a-a564-88353776683c" />


---

### 3️⃣ Weak Signing Key

**What breaks**  
JWTs are signed using weak or predictable HMAC secrets.

**Attack flow**
1. Capture a valid JWT
2. Brute-force the signing key
3. Re-sign token with elevated privileges

**Impact**
- Token forgery
- Full account compromise

**Mitigation**
- Use high-entropy secrets
- Rotate keys periodically

---

### 3️⃣ Weak Signing Key Attack Example

- Here we check for weak sining key that we can brute force
- Only suitable for symmetric key's like HS256
- We will copy jwt token and perfom offline attack to crack the key using hashcat [GPU-based] / use John the Ripper for [CPU-based]

  <img width="741" height="151" alt="Screenshot 2025-12-18 at 10 02 38 PM" src="https://github.com/user-attachments/assets/e6c4d604-dbf7-422c-b465-24a32ce18aea" />

<img width="912" height="374" alt="Screenshot 2025-12-18 at 10 02 25 PM" src="https://github.com/user-attachments/assets/1eea7713-1ae3-4ac3-b9e9-577102e09f97" />

- We will convert it using Burp decoder to base64

<img width="733" height="385" alt="Comparer" src="https://github.com/user-attachments/assets/47d8295f-3737-4b63-8376-601134538419" />

- We will create a new Symmetric Key using JWT Editor
- JWT Editor > New Symmetric Key > Generate > Replace k param with our cracked key 

<img width="1511" height="830" alt="Screenshot 2025-12-18 at 10 04 48 PM" src="https://github.com/user-attachments/assets/a45c1779-7197-4e46-bbfc-a69513681973" />

- We will modify our req here we have changed the user to admin and we will sign it with our genrated key and send the request

<img width="877" height="731" alt="Response" src="https://github.com/user-attachments/assets/95cc863e-517b-414a-9532-a66da703ee59" />

---
### 4️⃣ JWK Header Injection

**What breaks**  
The server trusts the `jwk` header supplied by the client.

**Exploitation logic**
- Embed attacker-controlled public key
- Sign token with matching private key
- Server verifies token using attacker-supplied key

**Impact**
- Complete authentication bypass

**Mitigation**
- Never accept keys from JWT headers
- Store verification keys server-side only
- Let's Genrate our Public key


---

### 4️⃣ JWK Header Injection Attack Example

- Here we will try to inject our own public key 
- If the application is misconfigured it will just accept any key and will not verify the key
- JWT Editor > New RSA Key > Genrate 
  <img width="1025" height="803" alt="Screenshot 2025-12-18 at 10 13 41 PM" src="https://github.com/user-attachments/assets/cd8bcbef-b397-47e1-8a23-18498a2a7257" />

- Let's Embedded JwK we will change the sub to admin sign it with our key and send the request 
  <img width="753" height="504" alt="Payload" src="https://github.com/user-attachments/assets/4dc4c63e-61d4-496a-9ff2-f255ae5e4ca9" />
  <img width="888" height="592" alt="Screenshot 2025-12-18 at 10 14 26 PM" src="https://github.com/user-attachments/assets/04b41f84-db44-4487-9ea0-0a17bc6ff960" />

---
### 5️⃣ JKU Header Injection

**What breaks**  
The server fetches signing keys from a URL specified in the JWT.

**Exploitation logic**
- Host a malicious JWKS
- Set `jku` to attacker-controlled URL
- Server fetches and trusts the key

**Impact**
- Authentication bypass
- Potential SSRF

**Mitigation**
- Use static, allow-listed key URLs
- Disable dynamic key fetching


---
### 5️⃣ JKU Header Injection Attack Example

- Here we will check if the applciation accepts arbitrary jiu parameter 
- First we will genrate a RSA key

<img width="937" height="676" alt="Screenshot 2025-12-18 at 10 22 54 PM" src="https://github.com/user-attachments/assets/1a6283a3-bcf9-4c7d-b717-ce3e19633254" />

- We will genrate our paylod body in exploit server
  
<img width="546" height="515" alt="View exploit" src="https://github.com/user-attachments/assets/46b91ce6-de3a-4029-9160-581007d03215" />

- We will copy our Public key as JWK

    <img width="496" height="357" alt="Burp Project Intruder Repeater" src="https://github.com/user-attachments/assets/15c66a48-7498-4763-a6a2-a11dd8bd708c" />

- Paste the key in exploit server and also replace the kid param with our genrated key 
    <img width="1047" height="746" alt="Screenshot 2025-12-18 at 10 27 12 PM" src="https://github.com/user-attachments/assets/81e231f8-115a-4b86-9d2f-a5972349456a" />

- Copy and Paste our Exploit server url to jku param
    <img width="1092" height="769" alt="injectio" src="https://github.com/user-attachments/assets/ed1c168c-0e1d-4cb3-afa4-9e7933aae193" />

- Lastly we change sub to admin will sign it with our genrated pub key and send the request
    <img width="1109" height="554" alt="Screenshot 2025-12-18 at 10 29 23 PM" src="https://github.com/user-attachments/assets/b6bb9ac5-933a-4f13-b9e6-8dbf3394b286" />


---
### 6️⃣ KID Header Path Traversal

**What breaks**  
The `kid` header value is mapped directly to filesystem paths.

**Exploitation logic**
- Inject path traversal payloads
- Force server to load unintended files as keys

**Impact**
- Authentication bypass
- Sensitive file access

**Mitigation**
- Treat `kid` as a logical identifier
- Use key-to-ID mapping, not filesystem paths


---
### 6️⃣ KID Header Path Traversal Attack Example 
- Here we will check if the kid paramener is vulnerable to path traverlsal or directly traversal
- We will also confirm if admin pannel exist 

  <img width="976" height="577" alt="ny-account7s6-wsener HTTP2" src="https://github.com/user-attachments/assets/13353c12-d899-446c-b523-aa74f24f8d45" />
  <img width="1082" height="563" alt="sapiene mietos isd tne arca w t0 01" src="https://github.com/user-attachments/assets/b047685c-952c-4dc4-b5cb-0a4fbffd1669" />

- We can try to change the sub to administrator but it won’t work because the signature will not match signature generated in backend

  <img width="772" height="591" alt="Request" src="https://github.com/user-attachments/assets/9c5aebb3-eafa-4316-92ce-bc4bc783a6ba" />

- Here we will sign it will dev/null file its a empty file that return empty string 
- So we will move up some files and use dev null key to sign it
- We will use "../../../../../../../../dev/null" payload for this
  
  <img width="788" height="593" alt="Request" src="https://github.com/user-attachments/assets/6cfeb070-2297-47ee-9ede-727fa3b225a8" />

- We will use this null signature to verify that it matches our null signed byte

  <img width="1082" height="335" alt="I Burp Project inder Repeater Yew trip" src="https://github.com/user-attachments/assets/7f460491-ef6f-4521-b4e0-290c005eb7ef" />

- Jwt Editor > New Symmetric key > Genrate> Edit the k param with our null signed byte

  <img width="1119" height="778" alt="Dup Poed" src="https://github.com/user-attachments/assets/7b77713f-dd3e-44ee-a2a5-34bd5f924be7" />

- Key generated

  <img width="782" height="177" alt="SfOacef8-1218-411  acbb 78cd0a54de87" src="https://github.com/user-attachments/assets/b036e8c7-3a36-42ea-9e74-682857d2b13e" />

- Use this key to sign > select our key > click ok

  <img width="902" height="702" alt="Response" src="https://github.com/user-attachments/assets/b76680f4-d83b-4a44-847f-2a268b35633c" />


- So basically, if it was vulnerable, it would cross-check /dev null we placed to AA== we placed, which would be the same as null and we will be able to exploit it

<img width="952" height="444" alt="Contest yor textinto charsetaut" src="https://github.com/user-attachments/assets/e2b71fa6-a39d-483a-afd8-ac3a0a9c9f1a" />

---

### 7️⃣ Algorithm Confusion (RS256 ↔ HS256)

**What breaks**  
The server supports both symmetric and asymmetric algorithms.

**Exploitation logic**
- Change `alg` from RS256 to HS256
- Use public key as HMAC secret
- Server validates token successfully

**Impact**
- Token forgery
- Administrative access

**Mitigation**
- Enforce strict algorithm allowlists
- Separate key usage by algorithm type

---

### 7️⃣ Algorithm Confusion (RS256 ↔ HS256) Attack Example

- We will check if the application is vulnerable to algorithm confusion attack also called as key confusion attack
- Before We perfom attack
- There are two types of keys sym (one key) and asym (two keys | public & private)
- Private key is used to sign the tokens
- Our goal here is to confuse the server we will use same algo to sign the token and verify the keys (Public Key)

- Here RS256 algo is used
- Websites generally store public keys at [domain]/jwks.json endpoint
  
  <img width="849" height="667" alt="HTTP2 200 ON" src="https://github.com/user-attachments/assets/a8b452d2-1153-405d-ba0a-851f340160e8" />

- Browser View
  
  <img width="1508" height="567" alt="(keys  (kty RSA, e AQA8, use 51g, kid 097b2e15" src="https://github.com/user-attachments/assets/8be4744a-1326-47ba-8bb1-02b59baff21d" />

- We will carefully copy selected section of key 

  <img width="922" height="188" alt="(keys 1(kty RSA, e AQAB, use sig  kid d97b2efs-" src="https://github.com/user-attachments/assets/2f7b5d66-92c2-414c-a40f-057e75f1b1a5" />

- Jwt Editor > New RSA key  > We will paste the content here 
   
  <img width="888" height="472" alt="El RSAKcy" src="https://github.com/user-attachments/assets/7135a953-3335-4579-bf30-9ababcfe487c" />

- Copy the content as Copy Public key as PEM 
  <img width="654" height="370" alt="Keys" src="https://github.com/user-attachments/assets/a34f2725-2b72-45a3-834e-3a27d14ea281" />

- Paste it in decoder and encode them as base64

  <img width="1050" height="356" alt="Screenshot 2026-01-13 at 5 01 23 PM" src="https://github.com/user-attachments/assets/b39dd385-8457-444d-bb4a-e6a8f3709ab8" />

- Copy the base64 genrated key we will use it as our new symmetric key 

-  JWT Editor > New Symmetric key  > Genrate > Paste the base64 content in k param 

  <img width="524" height="251" alt="RUenpNNzIKK1FJREFRQUIKLS0tLS1FTkQguFVCTELDIEtFWS0tLS0tCg==" src="https://github.com/user-attachments/assets/a715958c-2c9f-47fe-8e51-d4c0073e5928" />

- Modify the content with our intend here we will change alg and sub param with HS256 and admin

  <img width="331" height="293" alt="d97b2ef5-a3dd-48b0-99d8-7778" src="https://github.com/user-attachments/assets/1ccdb584-0c59-4f91-818d-2bbdb319e5c8" />

- Sign the payload with our genrated key

  <img width="741" height="628" alt="alized MT-" src="https://github.com/user-attachments/assets/be1c79b9-cfff-40b1-8118-5d5461c103e4" />

  <img width="1047" height="500" alt="Screenshot 2026-01-13 at 5 08 36 PM" src="https://github.com/user-attachments/assets/0c8608dc-0455-41f6-8967-857ff464d5f1" />

---

### 8️⃣ Algorithm Confusion with No Exposed Key

**What breaks**  
Key discovery through:
- Public JWKS endpoints
- Predictable configuration paths

**Impact**
- Same as classic algorithm confusion
- Full authentication bypass

**Mitigation**
- Restrict key exposure
- Secure key distribution mechanisms

---

## Common Root Causes

- Trusting client-controlled JWT headers
- Supporting multiple algorithms unnecessarily
- Weak or reused signing keys
- Improper error handling
- Missing claim validation

---

## 🛡️ Defensive Checklist

- ✔ Always verify JWT signatures
- ✔ Enforce strict algorithm allowlists
- ✔ Never trust `jwk` or `jku` headers
- ✔ Sanitize and validate `kid`
- ✔ Use strong, rotated signing keys
- ✔ Validate `exp`, `aud`, and `iss`
- Never decode tokens without verification

---

## ✍️ Author

**Karan Kurani**  
Cybersecurity | Web Security | Pentesting  

GitHub: https://github.com/karankurani
Linkedin: https://www.linkedin.com/in/karan-kurani/


