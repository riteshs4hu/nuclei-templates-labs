# OpenSSH Service - Detect

## Description:
- OpenSSH Detect refers to the process of identifying the presence and version of an OpenSSH service running on a system.
- OpenSSH is a widely used implementation of the Secure Shell (SSH) protocol, providing secure remote login, command execution, and file transfer capabilities. Detecting OpenSSH can help in assessing system security, identifying potential vulnerabilities, and ensuring compliance with security best practices.

## Reference:
- https://www.tenable.com/plugins/nessus/181418
- https://www.openssh.com/

## Vulnerable Setup

- Execute the following commands to start an OpenSSH server:

```bash
docker compose up -d
```

- After the server is started, you can connect to it using SSH on port 22. This server allows root login and requires authentication.

## Exploitation Steps

- Identify Open Ports:

Use nmap or naabu to check if port 22 (SSH) is open:

```bash
nmap -p 22 localhost
```

![image](https://github.com/user-attachments/assets/d85e4e68-817e-4cd9-b438-37d259070033)

- Banner Grabbing:

Retrieve the OpenSSH version using nc, telnet, or nmap:

```bash
nc -v localhost 22
```

![image](https://github.com/user-attachments/assets/30767c27-18c5-4bbe-9ad1-715506fbf4d2)

## Steps to Write Nuclei Template

**TCP Service Check**

```
tcp:
  - host:
      - "{{Hostname}}"
    port: 22
```

- Specifies the target host and checks **port 22** (default for SSH).
- Ensures the OpenSSH service is accessible over TCP.

**Matching OpenSSH Banner**

```
matchers:
  - type: regex
    regex:
      - '(?i)OpenSSH'
```

- Looks for the "**OpenSSH**" keyword in the SSH banner response.
- Uses a case-insensitive regex to identify OpenSSH presence.

**Extracting OpenSSH Version**

```yaml
extractors:
  - type: regex
    regex:
      - '(?i)SSH-(.*)-OpenSSH_[^\r]+'
```

- Extracts the **SSH protocol version** and **OpenSSH version** from the response.
- Helps in identifying outdated or vulnerable OpenSSH versions.

## Nuclei Template URL : [openssh-detect](https://github.com/projectdiscovery/nuclei-templates/blob/main/network/detection/openssh-detect.yaml)

## Nuclei Command :

```bash
nuclei -id openssh-detect -u localhost -vv
```

![image](https://github.com/user-attachments/assets/4f278dda-7355-42a4-a9fd-c5477df63ce5)
