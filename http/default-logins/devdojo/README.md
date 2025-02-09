# DevDojo Voyager Default Login

## Description:
DevDojo Voyager contains default credentials when run with dummy data. An attacker can obtain access to user accounts and access sensitive information, modify data, and/or execute unauthorized operations.

## Reference:
- https://voyager-docs.devdojo.com/getting-started/installation

## Vulnerable Setup

- Execute the following commands to start a Laravel Voyager 1.8.0 server:

```
docker compose up -d
```

- After the server is started, browse to http://your-ip:8000 to see the Laravel Voyager admin panel. This server requires authentication.

## Default Login   

Username: admin@admin.com

Password: password

# Exploitation Steps

- Navigate to your URL http://your-ip:8000/admin

- Enter the Default Credentials (admin@admin.com/password) as shown below.

![image](https://github.com/user-attachments/assets/7935b0f8-1966-44c9-9d35-21a8aac72e41)

- You will be Successfully Logged in with Admin Privilege.

# Steps to Write Nuclei Template

**Variables Section**

```yaml
variables:
  username: "admin@admin.com"
  password: "password"
```

- Defines the login credentials (username and password) as variables, which can be reused in requests.

**First Request: Retrieve CSRF Token**

```yaml
  - raw:
      - |
        GET /admin/login HTTP/1.1
        Host: {{Hostname}}

    extractors:
      - type: regex
        part: body
        internal: true
        name: csrf
        group: 1
        regex:
          - 'name="_token" value="([a-zA-Z0-9]+)"'
```

- Sends a GET request to /admin/login to retrieve the login page.
- Extracts the CSRF token (_token) from the response body using a regular expression.
- Stores the extracted value in an internal variable named csrf for later use.

**Second Request: Perform Login**

```yaml
  - raw:
      - |
        POST /admin/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        _token={{csrf}}&email={{username}}&password={{password}}&

    matchers:
      - type: dsl
        dsl:
          - "contains(body,'/admin</title>')"
          - "status_code == 302"
        condition: and
        internal: true
```

- Sends a POST request to `/admin/login` with:
  - Extracted `_token`
  - Username and password from the variables

- The matchers validate a successful login by checking:
  - The response body contains `</admin</title>` (indicating admin page access).
  - The response has a `302` status code, indicating a successful login and redirection.

## Nuclei Template URL : [devdojo-voyager-default-login](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/default-logins/devdojo/devdojo-voyager-default-login.yaml)

## Nuclei Command :

```bash
nuclei -t devdojo-voyager-default-login.yaml -u http://172.30.0.2:8000 -vv
```

