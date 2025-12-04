# DVWA Vulnerability Assessment Report

This report documents the identification, risk assessment, and remediation of 8 vulnerabilities in the Damn Vulnerable Web Application (DVWA).

## 1. Brute Force
**Location:** `vulnerabilities/brute/source/low.php`
**Description:** The login form allows unlimited login attempts, enabling attackers to guess passwords using automated tools.

**Risk Score:**
*   **Exploitability:** Easy (3)
*   **Weakness Prevalence:** Common (2)
*   **Weakness Detectability:** Easy (3)
*   **Technical Impacts:** Severe (3)
*   **Overall Risk:** High

**Fix:**
Implemented a delay (`sleep(2)`) after failed login attempts to slow down brute force attacks. Also updated the code to use prepared statements to prevent SQL Injection and `htmlspecialchars` to prevent XSS.

```php
// Check the database
$query  = "SELECT * FROM `users` WHERE user = ? AND password = ?";

if ($stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query)) {
    mysqli_stmt_bind_param($stmt, "ss", $user, $pass);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    if( mysqli_stmt_num_rows( $stmt ) == 1 ) {
        // ...
    }
    else {
        // Login failed
        sleep(2); // Anti-brute force
        $html .= "<pre><br />Username and/or password incorrect.</pre>";
    }
    mysqli_stmt_close($stmt);
}
```

## 2. Command Injection
**Location:** `vulnerabilities/exec/source/low.php`
**Description:** The application takes user input (IP address) and passes it directly to the `shell_exec` function, allowing attackers to execute arbitrary system commands.

**Risk Score:**
*   **Exploitability:** Easy (3)
*   **Weakness Prevalence:** Uncommon (1)
*   **Weakness Detectability:** Easy (3)
*   **Technical Impacts:** Severe (3)
*   **Overall Risk:** High

**Fix:**
Used `escapeshellarg()` to escape the user input before passing it to the shell command. This ensures the input is treated as a single argument and not interpreted as a command.

```php
// Get input
$target = $_REQUEST[ 'ip' ];

// FIX: Escape the argument to prevent command injection
$target = escapeshellarg($target);

// Determine OS and execute the ping command.
if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
    // Windows
    $cmd = shell_exec( 'ping  ' . $target );
}
```

## 3. Cross-Site Request Forgery (CSRF)
**Location:** `vulnerabilities/csrf/source/low.php`
**Description:** The password change functionality does not verify a CSRF token, allowing attackers to force users to change their password by tricking them into visiting a malicious link.

**Risk Score:**
*   **Exploitability:** Average (2)
*   **Weakness Prevalence:** Common (2)
*   **Weakness Detectability:** Average (2)
*   **Technical Impacts:** Moderate (2)
*   **Overall Risk:** Medium

**Fix:**
Added a check for the Anti-CSRF token (`user_token`) using `checkToken()`. Updated `index.php` to include the token in the form for the 'low' security level.

```php
if( isset( $_GET[ 'Change' ] ) ) {
    // FIX: Check Anti-CSRF token
    checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

    // Get input
    $pass_new  = $_GET[ 'password_new' ];
    // ...
}
```

## 4. File Inclusion
**Location:** `vulnerabilities/fi/source/low.php`
**Description:** The application includes a file specified by the `page` parameter without validation, allowing Local File Inclusion (LFI) or Remote File Inclusion (RFI).

**Risk Score:**
*   **Exploitability:** Easy (3)
*   **Weakness Prevalence:** Uncommon (1)
*   **Weakness Detectability:** Easy (3)
*   **Technical Impacts:** Severe (3)
*   **Overall Risk:** High

**Fix:**
Implemented a whitelist of allowed files (`include.php`, `file1.php`, etc.). The application now checks if the requested file is in the whitelist before including it.

```php
// The page we wish to display
$file = $_GET[ 'page' ];

// FIX: Whitelist allowed files to prevent File Inclusion
$allowed = array('include.php', 'file1.php', 'file2.php', 'file3.php');

if( !in_array( $file, $allowed ) ) {
    // This isn't the page we want!
    echo "ERROR: File not found!";
    exit;
}
```

## 5. SQL Injection
**Location:** `vulnerabilities/sqli/source/low.php`
**Description:** The application concatenates user input (`id`) directly into the SQL query, allowing attackers to manipulate the query to access unauthorized data.

**Risk Score:**
*   **Exploitability:** Easy (3)
*   **Weakness Prevalence:** Common (2)
*   **Weakness Detectability:** Easy (3)
*   **Technical Impacts:** Severe (3)
*   **Overall Risk:** High

**Fix:**
Replaced direct query concatenation with prepared statements using `mysqli_prepare` (for MySQL) and `prepare` (for SQLite). This separates code from data, preventing injection.

```php
// Check database
$query  = "SELECT first_name, last_name FROM users WHERE user_id = ?";
if ($stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query)) {
    mysqli_stmt_bind_param($stmt, "s", $id);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $first, $last);

    // Get results
    while(mysqli_stmt_fetch($stmt)){
        // Feedback for end user
        $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
    }
    mysqli_stmt_close($stmt);
}
```

## 6. File Upload
**Location:** `vulnerabilities/upload/source/low.php`
**Description:** The application allows uploading files without validating the type or extension, allowing attackers to upload malicious PHP scripts and execute them.

**Risk Score:**
*   **Exploitability:** Easy (3)
*   **Weakness Prevalence:** Common (2)
*   **Weakness Detectability:** Average (2)
*   **Technical Impacts:** Severe (3)
*   **Overall Risk:** High

**Fix:**
Implemented strict validation:
1.  Checked file extension (jpg, jpeg, png).
2.  Checked MIME type.
3.  Checked file size (< 100KB).
4.  Verified image validity using `getimagesize`.
5.  Renamed the uploaded file using a hash to prevent overwriting and execution of malicious filenames.

```php
// FIX: Validate file type and size
$uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
$uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
// ...

// FIX: Rename file to prevent overwriting and execution
$target_file   = md5( uniqid() . $uploaded_name ) . '.' . $uploaded_ext;
$target_path  .= $target_file;

if( ( strtolower( $uploaded_ext ) == 'jpg' || ... ) &&
    ( $uploaded_size < 100000 ) &&
    ( $uploaded_type == 'image/jpeg' || ... ) &&
    getimagesize( $uploaded_tmp ) ) {
        // Upload logic
}
```

## 7. Reflected XSS
**Location:** `vulnerabilities/xss_r/source/low.php`
**Description:** The application echoes user input (`name`) back to the browser without escaping, allowing attackers to inject malicious JavaScript.

**Risk Score:**
*   **Exploitability:** Average (2)
*   **Weakness Prevalence:** Widespread (3)
*   **Weakness Detectability:** Easy (3)
*   **Technical Impacts:** Moderate (2)
*   **Overall Risk:** High

**Fix:**
Used `htmlspecialchars()` to escape the output, converting special characters to HTML entities and preventing script execution.

```php
// Feedback for end user
// FIX: Escape output to prevent XSS
$html .= '<pre>Hello ' . htmlspecialchars($_GET[ 'name' ]) . '</pre>';
```

## 8. Stored XSS
**Location:** `vulnerabilities/xss_s/source/low.php`
**Description:** The application stores user input (message, name) in the database without sanitization. When displayed, the malicious script is executed in the victim's browser.

**Risk Score:**
*   **Exploitability:** Average (2)
*   **Weakness Prevalence:** Common (2)
*   **Weakness Detectability:** Average (2)
*   **Technical Impacts:** Moderate (2)
*   **Overall Risk:** Medium

**Fix:**
Sanitized the input using `htmlspecialchars()` before storing it in the database. Also implemented prepared statements to prevent SQL Injection.

```php
// Sanitize message input
$message = stripslashes( $message );
// FIX: Sanitize input to prevent Stored XSS
$message = htmlspecialchars( $message );

// ...

// Update database
// FIX: Use prepared statements
$query  = "INSERT INTO guestbook ( comment, name ) VALUES ( ?, ? )";

if ($stmt = mysqli_prepare($GLOBALS["___mysqli_ston"], $query)) {
    mysqli_stmt_bind_param($stmt, "ss", $message, $name);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_close($stmt);
}
```
