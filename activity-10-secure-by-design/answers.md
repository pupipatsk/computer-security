# Activity VIII: Secure Software / Simple Web Server - Answers

## Q1.1 (a) Connection Blocking
**Question:** What happens if a client connects to SimpleWebServer, but never sends any data and never disconnects? What type of an attack is this?

**Answer:**
If a client connects but sends no data (and doesn't disconnect), the single-threaded server blocks at `dServerSocket.accept()` or `br.readLine()` for that client. No other clients can connect or be served.
This is a **Denial of Service (DoS)** attack (specifically, a resource exhaustion/blocking attack).

## Q1.2 (b) Directory Traversal & /dev/random
**Question:** Try the DoS attack described in class: See if you can download /dev/random. Rewrite serveFile() to guard against this.

**Answer:**
On a Linux system, reading `/dev/random` would block indefinitely until enough entropy is gathered, causing a DoS. Additionally, accessing files like `/etc/passwd` via `../` is a **Directory Traversal** vulnerability.
We rewrote `serveFile()` (and `storeFile()`) to use `getCanonicalPath()` and check that the resolved path starts with the current working directory.

## Q1.3 (c) Logging
**Question:** Implement logging in SimpleWebServer.

**Answer:**
Logging has been implemented. The server now writes the timestamp, client IP, and request line to `server.log` for every request.

## Q1.4 (d) File Upload (PUT)
**Question:**
1. What threats would you need to consider if SimpleWebServer also provided functionality for uploading files?
2. What security mechanisms must be added?
3. Implement uploading capability.
4. Launch an attack to deface index.html.

**Answer:**
1.  **Threats:**
    *   **Malicious File Upload:** Uploading webshells (e.g., .jsp, .php) to execute code.
    *   **Overwriting Critical Files:** Replacing `index.html` (defacement) or system files (traversal).
    *   **Disk Space Exhaustion:** Uploading massive files to fill the disk (DoS).
    *   **Malware Hosting:** Using the server to host malware.

2.  **Security Mechanisms:**
    *   **Authentication:** Only allow authorized users to upload.
    *   **Path Sanitization:** Prevent directory traversal (implemented).
    *   **File Type Validation:** Whitelist allowed extensions (e.g., only .html, .jpg).
    *   **Size Limits:** Restrict maximum file size.
    *   **Storage Location:** Store uploads in a separate directory without execute permissions.

3.  **Implementation:** `PUT` support has been added to `SimpleWebServer.java` with path sanitization.

4.  **Defacement:** We successfully demonstrated overwriting `index.html` with a defaced version using `curl -T`.

## Q2 Securing New Web Server / Application
**Question:** What are the most important steps you would recommend for securing a new web server? A new web application?

**Answer:**
**Web Server:**
1.  **Hardening:** Disable unnecessary ports, services, and modules.
2.  **Patching:** Keep OS and server software updated.
3.  **Least Privilege:** Run as a non-root user.
4.  **Access Control:** Restrict file permissions.
5.  **Encryption:** Enforce HTTPS/TLS.

**Web Application:**
1.  **Input Validation:** Sanitize all inputs (headers, params, body).
2.  **Output Encoding:** Prevent XSS by encoding output.
3.  **Authentication/Authorization:** Strong passwords, MFA, and RBAC.
4.  **Session Management:** Secure cookies (HttpOnly, Secure), timeouts.
5.  **Error Handling:** Generic error messages (no stack traces).

## Q3 Cross-Site Scripting (XSS)
**Question:** What is "Cross-Site Scripting"? What is the potential security impact?

**Answer:**
**Definition:** XSS is a vulnerability where attackers inject malicious client-side scripts into web pages viewed by other users.
**Impact:**
*   **Session Hijacking:** Stealing cookies/tokens.
*   **Phishing:** Fake login forms.
*   **Redirection:** Sending users to malicious sites.
*   **Defacement:** Altering page content.

## Q4 Phishing and Pharming
**Question:** What are phishing and pharming? What are the ways to protect against such attacks?

**Answer:**
**Phishing:** Deceptive communication (email/SMS) mimicking a trusted source to steal sensitive data.
*   *Protection:* User awareness training, email authentication (SPF/DKIM), MFA.

**Pharming:** Redirecting traffic from a legitimate site to a fraudulent one (via DNS poisoning or host file modification).
*   *Protection:* DNSSEC, HTTPS (certificate validation), endpoint protection (antivirus/host file monitoring).

## Q5 OWASP Exploration
**Question:**
1. What are some of the vulnerabilities of web browsers?
2. What are some modes of attack used to implement a Denial of Service? What preventive measures can be implemented?

**Answer:**
1.  **Browser Vulnerabilities:**
    *   **XSS Execution:** Browsers trust code sent by the server.
    *   **Insecure Plugins/Extensions:** Vulnerable add-ons.
    *   **Man-in-the-Middle:** Trusting invalid/weak certificates.
    *   **CSRF:** Automatically sending credentials/cookies with requests.

2.  **DoS Attacks & Prevention:**
    *   *Modes:* Volumetric (UDP flood), Protocol (SYN flood), Application (HTTP flood, Slowloris).
    *   *Prevention:* Rate limiting, Load balancing, WAFs, Connection timeouts, Asynchronous processing.
