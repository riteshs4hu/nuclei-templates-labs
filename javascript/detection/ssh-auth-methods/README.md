# SSH Auth Methods - Detection

## Description:
Detects the authentication methods supported by an SSH service, such as publickey, password, and keyboard-interactive.This information helps assess authentication security and identify potential misconfigurations or weak authentication mechanisms.

## Reference:
- https://nmap.org/nsedoc/scripts/ssh-auth-methods.html
- https://github.com/mmcco/ssh-auth-methods

## Vulnerable Setup

- Execute the following commands to start an OpenSSH server:

```bash
docker compose up -d
```

- After the server is started, you can connect to it using SSH on port 22. This server allows root login and requires authentication.

## Exploitation Steps

- Send an SSH request to identify supported authentication methods:

```bash
ssh -o PreferredAuthentications=none -o PubkeyAuthentication=no localhost
```

- The response will list authentication methods, such as:

```bash
Permission denied (publickey,password,keyboard-interactive).
```

**Analyze the Output**

- publickey → SSH key-based authentication is enabled.
- password → Password-based authentication is allowed (potentially insecure).
- keyboard-interactive → Multi-step authentication method (e.g., OTP, challenge-response).

## Steps to Write Nuclei Template

**Check if the SSH Port is Open**

```yaml
pre-condition: |
  isPortOpen(Host,Port);
```

- Ensures the SSH port (22) is open before executing the detection logic.
- Prevents unnecessary requests to closed ports.

**Establish an SSH Connection**

```yaml
var m = require("nuclei/ssh");
var c = m.SSHClient();
var response = c.ConnectSSHInfoMode(Host, Port);
Export(response);
```

- Imports the SSH module (`nuclei/ssh`) for interacting with SSH services.
- Creates an SSH client (`c = m.SSHClient()`) to initiate a connection.
- Runs `ConnectSSHInfoMode(Host, Port)` to retrieve SSH authentication details.
- Exports the response for further analysis.

**Define Target Arguments**

```yaml
args:
  Host: "{{Host}}"
  Port: "22"
```

- Specifies the target host and port (default SSH port: 22).

**Extract Supported Authentication Methods**

```yaml
extractors:
  - type: json
    json:
      - '.UserAuth'
```

- Parses the JSON response from the SSH server.
- Extracts the `.UserAuth` field, which lists the supported authentication methods (e.g., publickey, password, keyboard-interactive).

## Nuclei Template URL : [ssh-auth-methods](https://github.com/projectdiscovery/nuclei-templates/blob/main/javascript/detection/ssh-auth-methods.yaml)

## Nuclei Command :

```bash
nuclei -id ssh-auth-methods -u localhost -vv
```

![image](https://github.com/user-attachments/assets/1871e6aa-629a-474b-a9e8-86b7a65927a2)
