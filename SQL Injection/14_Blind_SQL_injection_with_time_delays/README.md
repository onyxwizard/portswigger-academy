# Blind SQL Injection with Time Delays

## 🧪 **Lab Overview**

This lab demonstrates a **Blind SQL Injection** vulnerability that can be exploited using **time-based techniques**. The application uses a tracking cookie for analytics and performs a SQL query containing the value of this cookie. However, the results of the query are not returned to the user, and the application does not display any error messages or change its behavior based on the result.

Despite these restrictions, the SQL query is executed **synchronously**, which allows us to exploit the vulnerability by causing **conditional time delays** in the database processing. By triggering a 10-second delay in the response, we can confirm the presence of a SQL injection vulnerability.

## 🔍 **Objective**

Exploit the blind SQL injection vulnerability in the tracking cookie to cause a **10-second delay** in the server's response.

## 🛠️ **Tools Used**

- **Burp Suite** – For intercepting and modifying HTTP requests.
- **Foxy Proxy** – To route traffic through Burp.
- **Web Browser** – For interacting with the web application.
- **SQLi Cheatsheet** (from Web Security Academy) – For identifying time-based payloads.

## 🧩 **Vulnerability Details**

### Vulnerable Parameter
The `TrackingId` cookie used by the application is vulnerable to **blind SQL injection**.

### Behavior
- No output from the SQL query is reflected in the response.
- No visible errors or changes in application behavior.
- Query is processed **synchronously**, allowing us to use **time-based blind SQL injection**.

## ⚙️ **Exploitation Approach**

Since we cannot observe the output or errors from the SQL query, we use **time-based blind SQL injection**:

1. Inject a SQL payload into the `TrackingId` cookie.
2. Trigger a conditional delay in the database (e.g., `SLEEP()`).
3. Observe the server’s response time:
   - If the delay occurs, the payload was executed → SQL injection is possible.
   - If no delay occurs, try another payload or syntax.

## 📦 **Step-by-Step Exploitation**

### Step 1: Intercept Request
- Use **Foxy Proxy** to route traffic through **Burp Proxy**.
- Access the lab homepage and intercept the request in **Burp Proxy**.
- Send the intercepted request to **Repeater** for testing.

### Step 2: Identify Vulnerable Cookie
- The `TrackingId` cookie is passed to a backend SQL query.
- Modify this cookie to inject SQL payloads.

### Step 3: Try Time-Based Payloads
Use different payloads based on the likely database type (MySQL, PostgreSQL, MSSQL, Oracle):

#### Example Payloads (from Web Security Academy Cheatsheet)

| Database      | Payload |
|---------------|---------|
| MySQL         | `' || SLEEP(10)--` |
| PostgreSQL    | `' || pg_sleep(10)--` |
| Microsoft SQL | `' WAITFOR DELAY '0:0:10'--` |
| Oracle        | `' DBMS_PIPE.RECEIVE_MESSAGE('a',10)--` |

> 🔍 **Note**: You may need to URL encode the payload depending on how the cookie is parsed.

### Step 4: Test Each Payload
Try each payload one at a time, ensuring:
- The original SQL query remains valid (close quotes properly).
- Add comments (`--`, `/* */`) to prevent trailing characters from breaking the query.
- Observe the response time in Burp Repeater.

#### Successful Payload (PostgreSQL)
```sql
'|| pg_sleep(10)--
```

URL Encoded:
```text
%27%7C%7C%20pg_sleep%2810%29--%20
```

### Step 5: Confirm Delay
- When you send the modified cookie with the successful payload, the server should respond after approximately **10 seconds**.
- This confirms that the SQL injection worked and the database interpreted your command.

## ✅ **Solution Summary**

By injecting the following payload into the `TrackingId` cookie:

```sql
'|| pg_sleep(10)--
```

We triggered a **10-second delay** in the database, confirming the presence of a **blind SQL injection vulnerability**.

After submitting this request, the lab marks as **solved**.

## 🧠 **Key Takeaways**

- Blind SQL injection vulnerabilities can still be exploited even if no output is visible.
- Time-based attacks rely on observing **response timing** rather than content.
- Always test multiple payloads for different databases when the backend is unknown.
- Proper SQL injection hygiene (like parameterized queries) prevents such vulnerabilities.

## 📚 **Further Reading & Resources**

- [PortSwigger Web Security Academy - SQL Injection](https://portswigger.net/web-security/sql-injection)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [Time-Based SQL Injection Explained](https://owasp.org/www-community/attacks/Blind_SQL_Injection)

Thank you for watching and happy hacking! 🎯🔒
