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

## Exploitation Steps

- Run the following nmap command

```bash
nmap -sV --script=mysql-info localhost -p3306
```

![image](https://github.com/user-attachments/assets/37a5374d-5bc5-4ea1-a589-88ff37868ccf)

- if the Nmap `mysql-info` script reveals `mysql_native_password` in the **Auth Plugin Name**, then the server is using MySQL Native Password Authentication.

## Steps to Write Nuclei Template

**TCP Service Check**

```yaml
tcp:
  - host:
      - "{{Hostname}}"
    port: 3306
```

- Targets the MySQL service on port 3306.
- Ensures the service is reachable over TCP.

**Matching `mysql_native_password` Authentication Plugin**

```yaml
    matchers:
      - type: word
        words:
          - "mysql_native_password"
```

- Looks for "mysql_native_password" in the MySQL server's handshake response.
- Confirms that the MySQL server uses this authentication plugin, which can be vulnerable to brute-force attacks.

## Nuclei Template URL : [mysql-native-password](https://github.com/projectdiscovery/nuclei-templates/blob/main/network/misconfig/mysql-native-password.yaml)

## Nuclei Command :

```bash
nuclei -id mysql-native-password -u localhost -vv
```

![image](https://github.com/user-attachments/assets/8272bca0-ff94-4d43-be6a-a1f6486b6057)

