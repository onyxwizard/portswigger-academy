# 🎯 **Lab Walkthrough: SQL Injection with Filter Bypass via XML Encoding** 🎯  
## 📚 **Title**: *SQL Injection in Different Contexts – XML Injection with WAF Bypass*  

🎥 **Hi everyone!**  
we’ll be tackling a lab titled **"SQL injection with filter bypass via XML encoding"** — which is part of the broader topic **“SQL injection in different contexts”**.

We'll explore how attackers can inject malicious payloads into **XML-formatted input**, and how to **bypass WAF filters using XML encoding techniques** — both manually and with tools like **Hackvertor**. Let's dive in! 💻🔒

## 🔍 Lab Overview

- **Vulnerable Feature**: Stock check functionality
- **Input Format**: XML (`productId` and `storeId`)
- **Goal**: Retrieve admin credentials from the `users` table and log in as administrator
- **Challenge**: A WAF blocks standard SQLi keywords
- **Solution Strategy**: Inject SQL payload inside XML and **bypass WAF using XML character encoding**

> ⚠️ This lab demonstrates how SQL injection isn't limited to query strings or form inputs — it can appear in **any data format** processed by the backend SQL engine.

## 🧪 Step-by-Step Guide (With Manual Approach)

### 1️⃣ **Identify the Vulnerable Input**

📦 The application uses an XML-based stock check API:
```xml
<stockCheck>
    <productId>123</productId>
    <storeId>999</storeId>
</stockCheck>
```

🔧 Intercept this request using **Burp Suite**, then send it to **Repeater** for testing.

### 2️⃣ **Test if storeId is Evaluated**

Try injecting basic math expressions to see if the value is interpreted:
```xml
<storeId>1+1</storeId>
```

✅ If the response changes based on the result (e.g., returns stock from store ID 2), that confirms the input is being evaluated.

### 3️⃣ **Attempt UNION Attack**

Try a basic UNION attack to retrieve data:
```xml
<storeId>1 UNION SELECT NULL</storeId>
```

🚫 But you’ll notice the request gets blocked — likely due to WAF detecting SQL keywords like `UNION`, `SELECT`, etc.

### 4️⃣ **Bypass WAF Using XML Encoding (Manual Method)**

Since we're injecting into XML, we can use **XML entity encoding** to obfuscate SQL keywords.

#### Example: Encode `SELECT` as Hex or Decimal Entities

| Original | XML Entity | Description |
|---------|------------|-------------|
| `S`     | `&#x53;` or `&#83;` | Hex/Decimal representation of 'S' |
| `E`     | `&#x45;` or `&#69;` | And so on... |

So instead of:
```sql
UNION SELECT username || '~' || password FROM users
```

Use:
```sql
UNI&#x4f;&#x4e; SEL&#x45;CT username || '~' || password FRO&#x4d; users
```

You can break down each keyword into encoded characters to evade detection.

### 5️⃣ **Inject Encoded Payload Manually**

Update your XML payload like this:
```xml
<stockCheck>
    <productId>1</productId>
    <storeId>1 UNI&#x4f;&#x4e; SEL&#x45;CT username || '~' || password FRO&#x4d; users</storeId>
</stockCheck>
```

🔄 Send the request and observe the response.

🎉 If successful, you’ll see the list of usernames and passwords separated by `~`.

### 6️⃣ **Extract Admin Credentials**

From the response, locate the line containing:
```
administrator~<password>
```

📌 Copy the password and keep it handy.

### 7️⃣ **Log In as Administrator**

🔐 Go to `/my-account`  
📧 Enter:
- **Username**: `administrator`
- **Password**: Retrieved from the injection

🔓 Click **Login**

✅ Congratulations! You’ve solved the lab!

## 🛠️ Bonus: Use Hackvertor Extension (Optional)

If you have access to the **Hackvertor extension in Burp Suite**, you can automate the encoding:

1. Highlight your SQL payload in Repeater.
2. Right-click → **Extensions > Hackvertor > Encode > dec_entities or hex_entities**
3. It will auto-encode the payload using XML entities.
4. Replace the original `storeId` with the encoded string and send.

This saves time and ensures maximum obfuscation.

## 📝 Summary Checklist ✅

| Step | Action |
|------|--------|
| 🔹 | Identify XML-based input handling |
| 🔹 | Test `storeId` evaluation using arithmetic |
| 🔹 | Attempt basic UNION attack (blocked by WAF) |
| 🔹 | Encode SQL keywords using XML entities manually |
| 🔹 | Inject encoded payload via `storeId` |
| 🔹 | Extract admin credentials from response |
| 🔹 | Log in as administrator to complete the lab |
| 🔹 | (Optional) Use Hackvertor to automate encoding |

## 🧠 Key Takeaways

- SQL injection can occur in **any context** — not just URL parameters or form fields.
- Applications accepting **XML or JSON** input may still process it directly in SQL queries.
- WAFs often rely on pattern matching — **obfuscating payloads** using encodings helps bypass them.
- Understanding **character encoding** and **context-specific injection techniques** is crucial for advanced exploitation.

## 📚 Real-World Application

In real-world pentesting or bug bounty hunting:
- Always test all user-controllable inputs (headers, cookies, XML/JSON bodies).
- Use tools like Hackvertor or manual encoding to bypass security filters.
- Combine SQL injection with other vulnerabilities (like XXE or command injection) for deeper impact.

💬 Drop questions or thoughts in the comments — happy hacking! 🛠️👾

🔐 Until next time, stay secure and keep learning!  
