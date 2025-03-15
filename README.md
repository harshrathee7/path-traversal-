### **Path Traversal Attack (Directory Traversal)**
Path Traversal, also known as **Directory Traversal**, is a web security vulnerability that allows attackers to access files and directories stored outside the web root folder by manipulating file paths in user input.
- Application code and data.
- credential from back-end server.
- sensitive operating system files.

---

## **How Path Traversal Works**
Web applications often use user-supplied input to specify file paths. If the application does not properly sanitize this input, an attacker can manipulate file paths using special characters like:
- `../` (dot-dot-slash) → Moves up one directory
- `../../` → Moves up two directories
- `%2e%2e%2f` (URL encoded `../`)
- `..\\` (for Windows-based servers)

---

## **Common Exploitation Scenarios**
### **1. Accessing Sensitive Files**
If a web application loads files dynamically, an attacker can manipulate the file path to read system files:
```bash
http://example.com/view?file=../../../../etc/passwd
```
- **Linux Target:** `/etc/passwd`
- **Windows Target:** `C:\Windows\System32\config\SAM`

### **2. Reading Source Code Files**
An attacker might access application source code if file extensions are not properly restricted:
```bash
http://example.com/view?file=../../../../../var/www/html/config.php
```

### **3. Log File Exposure**
Attackers can extract logs for sensitive information:
```bash
http://example.com/view?file=../../../../var/log/apache2/access.log
```

---

## **Advanced Exploitation**
### **1. RFI (Remote File Inclusion) with Path Traversal**
Some applications allow **remote file inclusion** if combined with **path traversal**:
```bash
http://example.com/view?file=../../../../../../tmp/reverse_shell.php
```
An attacker may upload a malicious PHP file and execute it.

### **2. LFI (Local File Inclusion) to RCE (Remote Code Execution)**
If an application includes files without proper validation, an attacker can leverage **LFI to RCE**:
```bash
http://example.com/view?file=../../../../../var/log/apache2/access.log
```
If the log file contains malicious PHP code (e.g., injected via **User-Agent headers**), it could lead to **remote code execution (RCE)**.

---

## **How to Prevent Path Traversal Attacks**
###  **1. Use Absolute Paths**
Avoid using user-supplied input to construct file paths. Instead, define absolute paths in the backend:
```php
$allowed_files = ['about.html', 'contact.html'];
if (in_array($_GET['file'], $allowed_files)) {
    include($_GET['file']);
} else {
    die("Access Denied!");
}
```

###  **2. Input Validation**
Use a **whitelist approach** and allow only expected values:
```php
if (preg_match('/\.\./', $_GET['file'])) {
    die("Invalid file path!");
}
```

###  **3. Restrict File Access**
Use **chroot jails** or **containerized environments** to prevent access to sensitive directories.

###  **4. Disable Directory Listings**
Ensure the server does not expose directory listings (`Options -Indexes` in `.htaccess`).

###  **5. Use Web Application Firewalls (WAFs)**
A **WAF** can detect and block common path traversal attempts.

---

###  **vulnerabile parameter**

?cat={payload}
?dir={payload}
?action={payload}
?board={payload}
?date={payload}
?detail={payload}
?file={payload}
?download={payload}
?path={payload}
?folder={payload}
?prefix={payload}
?include={payload}
?page={payload}
?inc={payload}
?locate={payload}

---

## **Path Traversal Testing**
### **Manual Testing**
- Try `../` sequences to access system files
- Use **burp suite intruder** to automate testing
- Test encoded variations (`%2e%2e%2f`)

### **Automated Tools**
- **Burp Suite Scanner**
- **Nuclei** (with path traversal templates)
- **Nikto**
- **ffuf**
- **dotdotpwn** (specific for Path Traversal)
- **wfuzz**

