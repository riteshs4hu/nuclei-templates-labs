# SSH SHA-1 HMAC Algorithms Enabled

## Description:
The remote SSH server is configured to enable SHA-1 HMAC algorithms.

## Reference:
- https://www.tenable.com/plugins/nessus/153588
- https://www.virtuesecurity.com/kb/ssh-weak-mac-algorithms-enabled/

## Vulnerable Setup

- Execute the following commands to start an OpenSSH server:

```bash
docker compose up -d
```

- After the server is started, you can connect to it using SSH on port 22. This server allows root login and requires authentication.

## Exploitation Steps

- Nmap's `ssh2-enum-algos` script can enumerate supported HMAC algorithms:

```bash
nmap --script ssh2-enum-algos -p22 localhost
```

- Look for the MAC algorithms section in the output. If it includes hmac-sha1 or hmac-sha1-96, the server supports weak HMAC algorithms.

![image](https://github.com/user-attachments/assets/6b96dc78-85d9-4062-a187-af191160ec1d)

## Steps to Write Nuclei Template

**Pre-Condition Check**

```yaml
pre-condition: |
  isPortOpen(Host,Port);
```

- Ensures that the SSH port (default: 22) is open before running the detection logic.
- Prevents unnecessary requests to closed ports.

**JavaScript Execution Block**

```yaml
code: |
  let m = require("nuclei/ssh");
  let c = m.SSHClient();
  let response = c.ConnectSSHInfoMode(Host, Port);
  Export(response);
```

- Loads the `nuclei/ssh` module to interact with SSH services.
- Initializes an SSH client and connects using `info mode`, which retrieves SSH server details `without` authentication.
- Extracts and exports the response for further processing.

**Arguments Section**

```yaml
args:
  Host: "{{Host}}"
  Port: "22"
```

- Defines the target hostname/IP and SSH port (default: 22) as variables for flexibility.

**Matchers for Detection**

```yaml
matchers-condition: and
matchers:
  - type: word
    words:
      - "server_to_client_macs"
      - "client_to_server_macs"
    condition: and
```

- Ensures the response includes SSH MAC algorithm settings for both directions (`server_to_client_macs`, `client_to_server_macs`).
- Confirms the server shares SSH encryption configurations.

```yaml
  - type: word
    words:
      - "hmac-sha1"
```

- Checks if `hmac-sha1` is listed, indicating weak SHA-1-based HMAC algorithms are enabled.

## Nuclei Template URL : [ssh-sha1-hmac-algo](https://github.com/projectdiscovery/nuclei-templates/blob/main/javascript/enumeration/ssh/ssh-sha1-hmac-algo.yaml)

## Nuclei Command :

```bash
nuclei -id ssh-sha1-hmac-algo -u localhost -vv
```

![image](https://github.com/user-attachments/assets/ced7c07c-024b-4d88-a4b9-935210f9dd39)
