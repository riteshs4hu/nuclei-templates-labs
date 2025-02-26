# MySQL - Password Vulnerability

## Description:
- MySQL Native Password vulnerability refers to the use of the older, less secure mysql_native_password authentication method. This authentication method is vulnerable to password brute-force attacks and rainbow table attacks
- The vulnerability exists when MySQL is configured to use native password authentication instead of the more secure `caching_sha2_password` method

## Reference:
- https://dev.mysql.com/doc/refman/8.0/en/native-pluggable-authentication.html
- https://github.com/Tinram/MySQL-Brute

## Vulnerable Setup

- Execute the following commands to start a MySQL 5.7 server:

```bash
docker compose up -d
```

- After the server is started, you can connect to it using MySQL on port 3306. This server allows root login with the password `root123` and includes a test database with user credentials.

