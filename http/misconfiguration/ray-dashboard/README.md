# Ray Dashboard Exposure

## Lab Setup

- Run the following command to build and start the container:

  ```bash
  docker-compose up -d
  ```
Once the container is running, the Ray Dashboard will be available at: `http://localhost:8265`

## Exploitation Steps
- Open your web browser and navigate to: `http://your-ip:8265/`

## Steps to Write Nuclei Template  


**HTTP Requests**
```yaml
http:
  - method: GET
    path:
      - "{{BaseURL}}"
```
- This request attempts to load the root of the Ray Dashboard.

**Matchers: Detecting Access**
```yaml
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Ray Dashboard"

      - type: status
        status:
          - 200
```
- These matchers confirm:
    - The response status is 200 OK, indicating the page loaded successfully.
    - The body contains the string "Ray Dashboard", confirming that the exposed interface is indeed Ray's dashboard.

## Nuclei Template URL : [ray-dashboard](https://github.com/projectdiscovery/nuclei-templates/blob/main/http/misconfiguration/ray-dashboard.yaml)

## Nuclei Command

```bash
nuclei -id ray-dashboard -u localhost:8265 -vv
```