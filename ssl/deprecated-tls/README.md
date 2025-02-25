# Deprecated TLS Detection

## Description:
Deprecated versions of Transport Layer Security (TLS), such as TLS 1.0 and TLS 1.1, are considered insecure due to multiple cryptographic weaknesses. These older protocols lack modern security features like stronger cipher suites, resistance to downgrade attacks, and protection against known vulnerabilities such as BEAST, POODLE, and Lucky13. Attackers can exploit these weaknesses to intercept, decrypt, or manipulate sensitive data in transit. Due to these risks, major organizations and regulatory bodies have deprecated TLS 1.0 and 1.1 in favor of TLS 1.2 and TLS 1.3, which offer improved security and performance.

## Reference:
- https://ssl-config.mozilla.org/#config=intermediate
- https://www.tenable.com/plugins/nessus/157288
- https://help.defense.com/en/articles/6718613-tls-version-1-1-protocol-deprecated-windows-vulnerability

## Vulnerable Setup

1. Create directories and generate SSL cert

```bash
mkdir -p ssl
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout ssl/key.pem \
    -out ssl/cert.pem \
    -days 365 \
    -subj "/CN=localhost"
```

2. Start the server

```bash
docker-compose up -d
```

3. Test Vulnerable TLS

```bash
curl -vk --tlsv1.0 https://localhost
```

## Exploitation Steps

- Check the TLS Version using the following **nmap** command.

```bash
nmap -p 443 --script ssl-enum-ciphers localhost
```

![image](https://github.com/user-attachments/assets/fd45e3ea-8389-4de1-8d5f-b3d7ff270310)

## Steps to Write Nuclei Template

**TLS 1.1 Detection**

```yaml
  - address: "{{Host}}:{{Port}}"
    min_version: tls11
    max_version: tls11

    extractors:
      - type: json
        name: tls_1.1
        json:
          - ".tls_version"
```

- Targets only TLS 1.1 by setting `min_version` and `max_version` to tls11.
- Extracts and stores the TLS version under `tls_1.1`.

**TLS 1.0 Detection**

```yaml
  - address: "{{Host}}:{{Port}}"
    min_version: tls10
    max_version: tls10

    extractors:
      - type: json
        name: tls_1.0
        json:
          - ".tls_version"
```

- Checks if TLS 1.0 is supported.
- Extracts the version and stores it under `tls_1.0`.

**SSL 3.0 Detection**

```yaml
  - address: "{{Host}}:{{Port}}"
    min_version: ssl30
    max_version: ssl30

    extractors:
      - type: json
        name: ssl_3.0
        json:
          - ".tls_version"
```

- Tests for SSL 3.0, an outdated and insecure protocol.
- Extracts the version and stores it under `ssl_3.0`.

**General SSL/TLS Detection (Single Request for All)**

```yaml
  - address: "{{Host}}:{{Port}}"
    min_version: ssl30
    max_version: tls11

    extractors:
      - type: json
        name: ssl_tls_version
        json:
          - ".tls_version"
```

- Checks for any SSL/TLS version within the range SSL 3.0 → TLS 1.1.
- Extracts the detected version and stores it under `ssl_tls_version`.

## Nuclei Template URL : [deprecated-tls](https://github.com/projectdiscovery/nuclei-templates/blob/main/ssl/deprecated-tls.yaml)

## Nuclei Command :

```bash
nuclei -t nuclei-templates/ssl/deprecated-tls.yaml -u https://localhost -vv
```

![image](https://github.com/user-attachments/assets/049ed4ac-1502-4b5c-9f91-b0c9763f0f58)
