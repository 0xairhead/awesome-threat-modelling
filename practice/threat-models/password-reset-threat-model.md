# Password Reset Workflow Threat Model

This document outlines the STRIDE threat model for a password reset workflow and provides in-depth, practical implementation guidelines to mitigate each threat category securely.

## Table of Contents
- [1. STRIDE Threat Analysis Overview](#1-stride-threat-analysis-overview)
- [2. In-Depth Mitigations by Threat Category](#2-in-depth-mitigations-by-threat-category)
  - [2.1 Tampering: Securing the Token Payload (JWT)](#21-tampering-securing-the-token-payload-jwt)
    - [Step 1: Generating the Token (The Reset Request)](#step-1-generating-the-token-the-reset-request)
    - [Step 2: Validating and Applying the Reset (The Submission)](#step-2-validating-and-applying-the-reset-the-submission)
    - [Why "HTTPS Everywhere" is Critical Here](#why-https-everywhere-is-critical-here)
  - [2.2 Spoofing: Preventing Impersonation](#22-spoofing-preventing-impersonation)
    - [1. Generating Cryptographically Secure Tokens](#1-generating-cryptographically-secure-tokens)
    - [2. Enforcing Short Expiration Times](#2-enforcing-short-expiration-times)
    - [3. Requiring Multi-Factor Authentication (MFA)](#3-requiring-multi-factor-authentication-mfa)
  - [2.3 Repudiation: Building an Audit Trail](#23-repudiation-building-an-audit-trail)
    - [1. Comprehensive Logging (The Audit Trail)](#1-comprehensive-logging-the-audit-trail)
    - [2. Immediate Notifications (The "Out-of-Band" Alert)](#2-immediate-notifications-the-out-of-band-alert)
  - [2.4 Information Disclosure: User Enumeration Anti-Patterns](#24-information-disclosure-user-enumeration-anti-patterns)
    - [1. The "Helpful" Error Message (The most common flaw)](#1-the-helpful-error-message-the-most-common-flaw)
    - [2. The Timing Attack (The subtle flaw)](#2-the-timing-attack-the-subtle-flaw)
    - [3. Leaking the Raw Token in Logs](#3-leaking-the-raw-token-in-logs)
  - [2.5 Denial of Service: Endpoint Protection](#25-denial-of-service-endpoint-protection)
    - [1. Rate Limiting (Throttling)](#1-rate-limiting-throttling)
    - [2. Implement a CAPTCHA](#2-implement-a-captcha)
    - [3. DO NOT Lock the Account](#3-do-not-lock-the-account)
  - [2.6 Elevation of Privilege: Token Invalidation](#26-elevation-of-privilege-token-invalidation)
    - [Approach 1: The Database Method (Stateful Tokens)](#approach-1-the-database-method-stateful-tokens)
    - [Approach 2: The JWT Method (Stateless "Statefulness")](#approach-2-the-jwt-method-stateless-statefulness)

---

## 1. STRIDE Threat Analysis Overview

| STRIDE Category | Threat Description in Workflow | Potential Mitigation |
| :--- | :--- | :--- |
| **Spoofing** (Impersonating another user) | An attacker uses a leaked, guessed, or stolen reset token/link to impersonate a legitimate user and set a new password. | Use long, cryptographically secure random tokens. Enforce short token expiration times (e.g., 15 minutes). Require multi-factor authentication (MFA) before allowing the final password change. |
| **Tampering** (Modifying data) | An attacker intercepts the HTTP request during the final password submission and changes the target `user_id` parameter to reset someone else's password. | Cryptographically sign tokens (e.g., JWT) and bind them directly to the user's ID on the backend. Never rely on client-supplied user IDs during the reset submission. Use HTTPS everywhere. |
| **Repudiation** (Claiming you didn't do something) | A user changes their password, performs malicious activity, and later claims their account was hacked and they didn't authorize the password change. | Log all reset requests, token generations, and successful updates (including timestamps and IP addresses). Send an immediate "Your password was just changed" email notification to the user to create an audit trail. |
| **Information Disclosure** (Exposing private data) | Username Enumeration: The system returns different messages like "Email sent" vs. "User not found," allowing an attacker to harvest valid email addresses. | Use a generic response for all requests: "If that email is in our system, a password reset link has been sent." Never log the raw token in your application logs. |
| **Denial of Service** (Making the system unavailable) | An attacker floods the password reset endpoint with requests, exhausting the application's email/SMS quota or intentionally locking out legitimate users. | Implement strict rate limiting and CAPTCHA on the reset request endpoint. Do not lock the user's account just because a password reset was requested. |
| **Elevation of Privilege** (Doing things you shouldn't) | A flaw in the authorization logic allows a standard user's reset token to be used to change an administrator's password, or an old token is reused after roles change. | Invalidate tokens immediately after they are used once. Invalidate all previous tokens if a new reset request is made. Ensure the token strictly enforces the authorization boundary of the specific user it was issued to. |

---

## 2. In-Depth Mitigations by Threat Category

### 2.1 Tampering: Securing the Token Payload (JWT)

This is the exact right approach to prevent attackers from hijacking the reset process. By embedding the user's ID directly into a signed JWT (JSON Web Token), you make the token the absolute source of truth.

If an attacker intercepts the request and tries to change a `user_id=123` parameter to `user_id=1`, the backend simply ignores it, because it only trusts the ID locked securely inside the token.

Here is how you implement this in practice, using Node.js and the popular `jsonwebtoken` library as an example.

#### Step 1: Generating the Token (The Reset Request)

When the user requests a password reset, you verify their email, find their user record, and generate a token. You place their unique ID inside the token's payload.

```javascript
const jwt = require('jsonwebtoken');

// 1. User requests a reset with their email
const user = database.findUserByEmail(req.body.email);

if (user) {
  // 2. Define the payload. This is the data you are cryptographically signing.
  const payload = {
    userId: user.id,            // Bind the token explicitly to this user
    purpose: 'password_reset'   // Ensure this token can't be used for login
  };

  // 3. Sign the token with a strong, backend-only secret
  // Enforce a strict, short expiration (e.g., 15 minutes)
  const resetToken = jwt.sign(payload, process.env.JWT_SECRET_KEY, { 
    expiresIn: '15m' 
  });

  // 4. Send the token via email (usually as a URL query parameter)
  // Example: https://yoursite.com/reset-password?token=eyJhbGciOiJIUz...
  emailService.sendResetLink(user.email, resetToken);
}
```

#### Step 2: Validating and Applying the Reset (The Submission)

When the user submits their new password, the client sends the new password and the token. **The client does not send the user ID.** 

```javascript
// The client posts to: /api/reset-password
// Body contains: { token: "eyJhb...", newPassword: "SuperSecret123!" }

const jwt = require('jsonwebtoken');

function handlePasswordReset(req, res) {
  const { token, newPassword } = req.body;

  try {
    // 1. Verify the signature and expiration.
    // If the token was tampered with or expired, this throws an error.
    const decodedPayload = jwt.verify(token, process.env.JWT_SECRET_KEY);

    // 2. Verify the purpose of the token
    if (decodedPayload.purpose !== 'password_reset') {
        throw new Error("Invalid token type");
    }

    // 3. EXTRACT THE USER ID FROM THE TOKEN
    // This is the core mitigation. You completely ignore any user ID 
    // the client might have tried to send.
    const targetUserId = decodedPayload.userId;

    // 4. Hash the new password and update the database
    const hashedPassword = hashPassword(newPassword);
    database.updateUserPassword(targetUserId, hashedPassword);

    res.status(200).send("Password successfully updated.");

  } catch (error) {
    // This catches expired tokens, invalid signatures, etc.
    res.status(400).send("Invalid or expired reset token.");
  }
}
```

#### Why "HTTPS Everywhere" is Critical Here

A JWT is a "bearer token." This means whoever possesses the token can use it. 
* The cryptographic signature protects the token from being **modified**. 
* HTTPS protects the token from being **stolen**. 

If your site allows HTTP traffic, an attacker on the same public Wi-Fi network as your user could intercept the network traffic, read the JWT in plain text as it travels to your server, and use it themselves before the user does.

---

### 2.2 Spoofing: Preventing Impersonation

To further secure the reset flow, robust mitigation against **Spoofing** entails three core practices:

#### 1. Generating Cryptographically Secure Tokens

If using the **JWT approach** discussed above, rely on a strong secret and the HMAC algorithm. This makes forging a token practically impossible.

If utilizing **database-backed tokens** (saving a random string in your database), **never use `Math.random()`**. You must use a true cryptographic random number generator, such as the built-in `crypto` module in Node.js:

```javascript
const crypto = require('crypto');

// Generate 32 bytes of random data and convert it to a hex string
// This creates a 64-character, highly secure random token
const resetToken = crypto.randomBytes(32).toString('hex');
```

#### 2. Enforcing Short Expiration Times

**If using JWTs:** As shown earlier, pass `expiresIn: '15m'`. The `jsonwebtoken` library will automatically reject any token older than 15 minutes.

**If using a database:** Store an `expires_at` timestamp in your database securely alongside the token. When validating the token, verify the current time is before the expiration timestamp.

```javascript
// Example: Set expiration for 15 minutes from now
const expiresAt = new Date(Date.now() + 15 * 60 * 1000); 
```

#### 3. Requiring Multi-Factor Authentication (MFA)

If the user has MFA enabled (e.g., via Authenticator app or SMS), a password reset is a critical lifecycle action that *must* prompt them for it. An attacker stealing an email account to click the reset link cannot change the password without also possessing the user's second factor.

**Implementation Flow:**
1. User clicks the email link.
2. The frontend validates the token and renders an "Enter your MFA Code" screen prior to (or alongside) the "New Password" screen.
3. The user submits their MFA code and their reset token (and implicitly the new password).

```javascript
// Example modification to the final submission
function handlePasswordReset(req, res) {
  const { token, newPassword, mfaCode } = req.body;

  try {
    const decodedPayload = jwt.verify(token, process.env.JWT_SECRET_KEY);
    const user = database.findUserById(decodedPayload.userId);

    // If the user has MFA enabled, verify the code before allowing the reset
    if (user.mfaEnabled) {
      const isMfaValid = mfaService.verifyCode(user, mfaCode);
      if (!isMfaValid) {
        return res.status(401).send("Invalid MFA code.");
      }
    }

    // ... proceed with hashing and saving the new password
  } catch (error) {
    res.status(400).send("Invalid or expired reset token.");
  }
}
```

---

### 2.3 Repudiation: Building an Audit Trail

**Repudiation** happens when a user legitimately changes their password (and perhaps does something malicious with the account afterward), and then later claims "I was hacked! I never changed my password!"

If you don't have logs, it's a "their word against yours" situation. To build a solid audit trail, you need two things: **Comprehensive Logging** and **Immediate Notifications**.

#### 1. Comprehensive Logging (The Audit Trail)

You must log *every* critical step of the password reset lifecycle. A standard application log (using a library like Winston or Pino in Node.js) isn't enough; these events should ideally be stored in a dedicated security audit table in your database, or forwarded to a secure log management system (like Splunk or Datadog) where they cannot be easily deleted.

You need to record:
*   **What happened:** (e.g., `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET_SUCCESS`, `PASSWORD_RESET_FAILED`)
*   **Who did it:** The supposed `userId` or `email`.
*   **When it happened:** A precise UTC timestamp.
*   **Where it came from:** The IP address and User-Agent (browser info) of the requester.

```javascript
// Example: Logging a successful reset
function logSecurityEvent(eventType, userId, req, details = {}) {
  const auditLog = {
    event_type: eventType,
    user_id: userId,
    timestamp: new Date().toISOString(),
    ip_address: req.ip || req.connection.remoteAddress,
    user_agent: req.get('User-Agent'),
    details: details
  };

  // Insert this into an 'audit_logs' database table or send to a logging service
  database.insertAuditLog(auditLog);
}

// ... inside your handlePasswordReset function (after success):
logSecurityEvent('PASSWORD_RESET_SUCCESS', targetUserId, req);
```

#### 2. Immediate Notifications (The "Out-of-Band" Alert)

As soon as the password is mathematically changed in the database, you MUST send an email to the user. This creates an immediate feedback loop.

If they *did* change it, it's a nice confirmation.
If they *didn't* change it, they know instantly that their account in compromised, and they can contact your support team *before* the attacker has time to do serious damage.

```javascript
// Example: Sending the confirmation email immediately after changing the password
function handlePasswordReset(req, res) {
  // ... (JWT validation and password hashing steps we did earlier) ...

  database.updateUserPassword(targetUserId, hashedPassword);
  
  // 1. Log the audit trail
  logSecurityEvent('PASSWORD_RESET_SUCCESS', targetUserId, req);

  // 2. Fetch the user's email 
  const user = database.findUserById(targetUserId);

  // 3. Send the notification ASAP
  // Make sure this email tells them what to do if THEY DIDN'T request this 
  // (e.g., "Reply to this email" or "Call our fraud department immediately")
  emailService.sendPasswordChangedNotification(
    user.email, 
    {
      time: new Date().toISOString(),
      ip: req.ip // Including the IP in the email helps them spot exactly where the attack came from
    }
  );

  res.status(200).send("Password successfully updated.");
}
```

By combining these two factors, if a user ever claims they didn't authorize a password change, you can say: *"Our audit logs show the request came from your home IP address, and we sent a notification to your email at 2:00 PM and you did not report any fraud until 3 days later."*

---

### 2.4 Information Disclosure: User Enumeration Anti-Patterns

The goal of Username (or Email) Enumeration is for an attacker to figure out exactly who uses your service. They take a massive list of leaked emails from another website, run a script against your password reset endpoint, and see which ones belong to registered users.

If they confirm an email exists on your site, they can target that specific user with spear-phishing or credential stuffing attacks.

Here are the most common **Anti-Patterns (How NOT to do it)** that enable this attack:

#### 1. The "Helpful" Error Message (The most common flaw)

**DO NOT DO THIS:**
```javascript
// BAD IMPLEMENTATION
function requestReset(req, res) {
  const user = database.findUserByEmail(req.body.email);
  
  if (!user) {
    // ❌ ANTI-PATTERN: You just told the attacker this email isn't in your database.
    return res.status(404).json({ error: "No user found with that email address." });
  }

  // ... send email ...
  // ❌ The attacker now knows this email IS legitimate.
  return res.status(200).json({ message: "A reset link has been sent to your email." }); 
}
```

**Why it's bad:** An automated script can just look at the HTTP status codes (200 vs 404) or the JSON text to cleanly separate the valid emails from the invalid ones.

#### 2. The Timing Attack (The subtle flaw)

Even if you fix the messages to be identical, an attacker might still be able to enumerate users based on *how long* your server takes to reply.

**DO NOT DO THIS:**
```javascript
// BAD IMPLEMENTATION
function requestReset(req, res) {
  const user = database.findUserByEmail(req.body.email);
  
  if (user) {
    const token = generateToken();
    // ❌ ANTI-PATTERN: Sending an email over SMTP or an API takes time (e.g., 500ms - 2000ms)
    emailService.sendRealEmail(user.email, token); 
  }

  // ❌ If the user doesn't exist, this line runs instantly (e.g., 10ms)
  // The attacker measures the response time. Fast = fake user. Slow = real user.
  return res.status(200).json({ message: "If you exist, we sent an email." });
}
```

**Why it's bad:** A script will send 1000 requests. 990 of them return in `15ms`. 10 of them return in `1200ms`. The attacker now knows those 10 specific emails belong to real users.

**How to fix the Timing Attack:** 
You should offload the heavy work (email sending) to a background worker queue (like Celery, BullMQ, or AWS SQS). The HTTP Request just throws the job onto the queue and returns *immediately*, regardless of whether the user exists or not.

#### 3. Leaking the Raw Token in Logs

Another form of Information Disclosure isn't to the outside world, but to your internal team or log aggregators.

**DO NOT DO THIS:**
```javascript
// BAD IMPLEMENTATION
function requestReset(req, res) {
  const user = database.findUserByEmail(req.body.email);
  if (user) {
    const token = generateToken();
    
    // ❌ ANTI-PATTERN: You are dumping the plaintext token into Splunk/Datadog
    // Now any developer, support rep, or attacker who breaches your logs can 
    // click this link and reset the user's password themselves.
    console.log(`Sending reset link: https://yoursite.com/reset?token=${token}`);
    
    // ... send email ...
  }
}
```

**Why it's bad:** This violates the principle of least privilege. Your logging systems should never contain sensitive, actionable credentials. If you must log the token for debugging, log a *hash* of the token instead.

---

### 2.5 Denial of Service: Endpoint Protection

If you don't secure your reset endpoints, an attacker can launch a **Denial of Service (DoS)** or Distributed Denial of Service (DDoS) attack to degrade your application's availability. Attackers can spam the 'Request Reset' endpoint to exhaust your email or SMS quotas (costing you money or preventing legitimate users from getting their notifications). They can also try to intentionally trigger account lockouts if your logic is flawed.

To mitigate this, implement the following defenses:

#### 1. Rate Limiting (Throttling)

Rate limit the endpoint by both IP address and Target Email Address.

*   **By IP Address:** Prevents a single attacker machine from flooding requests.
*   **By Email Address:** Prevents a distributed botnet from draining an individual user's inbox with reset emails.

```javascript
// Example using express-rate-limit in Node.js
const rateLimit = require('express-rate-limit');

// 1. Limit requests per IP (e.g., max 5 requests per 15 minutes)
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5,
  message: "Too many requests from this IP, please try again after 15 minutes",
});

// 2. Limit requests per Target Email
// (This requires a custom store/logic but is conceptually similar)
// If the email 'victim@example.com' has requested a reset 3 times in the last hour, 
// silently drop the request but return a 200 OK to prevent enumeration.
```

#### 2. Implement a CAPTCHA

Before processing the reset request, require human validation using reCAPTCHA, hCaptcha, or Turnstile. This is highly effective against automated botnets scripts that blindly hammer endpoints.

#### 3. DO NOT Lock the Account

A common mistake is thinking: *"If someone requests a password reset 10 times, I should lock their account for safety."* 

**DO NOT DO THIS.** If you lock an account upon a password reset request, an attacker can simply type in the usernames of your CEO or top customers, click "Reset" 10 times, and instantly lock them out of the platform. The password reset flow should *never* negatively impact the target user's current session or access state.

---

### 2.6 Elevation of Privilege: Token Invalidation

A critical mitigation for **Elevation of Privilege** in a password reset workflow is ensuring that tokens **cannot be reused** and that requesting a new token **invalidates previous ones**. If a user's role changes (e.g., they become an Admin) and they have an old (but unexpired) reset token lying around, an attacker who compromised their email could use that old token to gain elevated access.

Here is how you effectively implement single-use tokens and strict invalidation.

#### Approach 1: The Database Method (Stateful Tokens)

If you are saving random token strings within your database, invalidation is straightforward but requires strict database management.

1.  **Invalidate on New Request:** Before generating a new token, delete or mark as `used=true` any existing tokens for that user.
2.  **Invalidate on Use:** The moment the password is changed, the token must be burned.

```javascript
// Stateful Approach: Validating and Burning the Token
async function handlePasswordReset(req, res) {
  const { token, newPassword } = req.body;

  // 1. Find the active token in the DB
  const pendingReset = await database.findActiveResetToken(token);
  
  if (!pendingReset || pendingReset.expiresAt < new Date()) {
    return res.status(400).send("Invalid or expired token.");
  }

  // 2. Perform the critical action
  const hashedPassword = hashPassword(newPassword);
  await database.updateUserPassword(pendingReset.userId, hashedPassword);

  // 3. BURN THE TOKEN. 
  // Do not let this transaction complete without deleting the token!
  await database.deleteResetToken(token);
  
  // (Optional but recommended) Burn ALL other tokens for this user just in case
  await database.deleteAllUserTokens(pendingReset.userId);

  return res.status(200).send("Password updated.");
}
```

#### Approach 2: The JWT Method (Stateless "Statefulness")

Because standard JWTs are stateless (the backend just checks the math on the signature), a 15-minute token remains valid for exactly 15 minutes, even *after* the user successfully changes their password. If an attacker gets the token 2 minutes after the user used it, they could potentially change the password again.

If an attacker intercepts the JWT, they can theoretically use it multiple times within its 15-minute lifespan. To fix this, you must bind the token's validity to a state that *changes* upon exactly one use: **The user's current password hash.**

**How to do it:** Include a portion of the user's *current* hashed password in the JWT `secret` used for signing.

**Step 1: Generating the Token (Binding to the Hash)**
```javascript
function requestReset(req, res) {
  const user = database.findUserByEmail(req.body.email);
  if (!user) return res.status(200).send("If you exist..."); 

  // The Secret is NOT just a static environment variable anymore.
  // It is dynamically combined with the user's CURRENT password hash.
  const dynamicSecret = process.env.JWT_SECRET_KEY + user.passwordHash;

  const payload = { userId: user.id, purpose: 'password_reset' };
  
  // Sign the token using this dynamic secret
  const resetToken = jwt.sign(payload, dynamicSecret, { expiresIn: '15m' });
  
  emailService.sendResetLink(user.email, resetToken);
}
```

**Step 2: Validating the Token (The Auto-Invalidation)**
```javascript
function handlePasswordReset(req, res) {
  const { token, newPassword } = req.body;
  
  // You need the target user ID *before* you can verify the signature.
  // jwt.decode() reads the payload without verifying. Do NOT trust this payload yet!
  const unverifiedPayload = jwt.decode(token); 
  const user = database.findUserById(unverifiedPayload.userId);

  // Reconstruct the exact same dynamic secret
  const dynamicSecret = process.env.JWT_SECRET_KEY + user.passwordHash;

  try {
    // NOW verify the signature cryptographically.
    // If the user's password changed since this token was generated, 
    // `user.passwordHash` is different -> `dynamicSecret` is different -> Signature FAILS.
    const decodedPayload = jwt.verify(token, dynamicSecret);
    
    // The signature is valid! This proves it is the exact token we issued,
    // AND the password has not been changed yet.

    const newHashedPassword = hashPassword(newPassword);
    database.updateUserPassword(user.id, newHashedPassword);
    
    // The moment the DB updates, `user.passwordHash` changes.
    // This instantly invalidates this token and ALL other pending JWTs for this user.

    res.status(200).send("Password successfully updated.");
  } catch (error) {
    // If the token was already used once, it throws an invalid signature error here.
    res.status(400).send("Invalid or expired reset token.");
  }
}
```

By tightly coupling the authentication token to the user's current entity boundary (their password hash), you guarantee strict, mathematically enforced token single-use, preventing elevation of privilege through reuse.
