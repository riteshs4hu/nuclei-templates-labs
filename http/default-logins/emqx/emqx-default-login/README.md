# EMQX Default Login

## Description:
EMQX is an open-source MQTT broker that provides a web-based Dashboard for management and monitoring.By default, EMQX includes predefined administrative credentials, which, if not changed, can pose security risks.An attacker could leverage these default credentials to gain unauthorized access, potentially leading to exposure of sensitive information, data modification, or execution of unauthorized operations.

## Reference:
- https://docs.emqx.com/en/emqx/latest/dashboard/introduction.html

## Vulnerable Setup

- Execute the following commands to start a EMQX Dashboard server:

```bash
docker compose up -d
```

- After the server is started, browse to http://localhost:18083/#/login?to=/dashboard/overview to see the EMQX Dashboard Panel.This server requires authentication.

## Default Login   

Username: admin

Password: public

## Exploitation Steps

- Navigate to the EMQX Dashboard at http://localhost:18083

- Enter the default credentials (admin / public).

- Upon successful login, you will have administrative access to the EMQX Dashboard.

## Steps to Write Nuclei Template

### Variables Section

Define the login credentials as variables for reuse in requests:

```
variables:
  username: "admin"
  password: "public"
```

### Request: Perform Login

Send a POST request to the EMQX authentication endpoint with the defined credentials:

```
- raw:
    - |
      POST /api/v5/login HTTP/1.1
      Host: {{Hostname}}
      Content-Type: application/json

      {"username":"{{username}}","password":"{{password}}"}

    matchers:
      - type: dsl
        dsl:
          - contains(body, "\"token\":") && contains(body, "\"license\":")
          - contains(content_type, 'application/json')
          - status_code == 200
        condition: and
```

This template attempts to authenticate using the default credentials and checks for a successful login response.

## Nuclei Template URL [emqx-default-login](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/default-logins/emqx/emqx-default-login.yaml)

## Nuclei Command :

```bash
nuclei -id emqx-default-login -u http://localhost:18083 -vv
```

![image](https://github.com/user-attachments/assets/5e3a50a2-57f1-4af3-aefd-f172ebafd381)
