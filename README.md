# 🎯 Nuclei-Templates-Labs

A comprehensive collection of vulnerable environments paired with ready-to-use Nuclei templates for security testing and learning! 🚀

## 🎭 Overview

**Nuclei-Templates-Labs** is your ultimate playground for:
- Hands-on security testing with real-world scenarios
- Step-by-step guides to exploit vulnerabilities
- Ready-to-use Nuclei templates for quick detection
- Practical learning with vulnerable environments

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/projectdiscovery/nuclei-templates-labs.git
cd nuclei-templates-labs
```

### 2. Install Dependencies

- Ensure you have **Docker** and **Docker Compose** installed.

```bash
# Install Docker (if not installed)
sudo apt update && sudo apt install docker.io -y

# Install Docker Compose
sudo apt install docker-compose -y
```

### 3. Launch the Vulnerable Environment

- Navigate to the specific directory for the lab and follow the setup instructions. Each lab may contain a `docker-compose.yml` file or other setup instructions.

- For example, if setting up CVE-2024-55416, move to its directory and follow the appropriate setup steps:

```bash
cd http/cve/2024/CVE-2024-55416
docker-compose up -d  # If a docker-compose.yml file is present
```

- Refer to the lab's documentation for any additional setup requirements.

### 4. Install Nuclei

- If you haven’t installed Nuclei yet, run:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Or download from [ProjectDiscovery's releases](https://github.com/projectdiscovery/nuclei/releases).

- Verify the installation:
```bash
nuclei -version
```

## 📄 Lab Scenarios
Each lab scenario comes with:
- A **vulnerable service** in a Docker container
- A **detailed exploitation guide** to walk you through
- A **matching Nuclei template** for easy detection

## 🏆 Contributing
We welcome contributions! If you’d like to:
- Add new vulnerable labs
- Improve existing templates
- Report issues

Please create a pull request or open an issue.

## 🎨 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🐝 Stay Connected
- Follow [ProjectDiscovery](https://github.com/projectdiscovery) for more security tools.
- Join our [community](https://discord.gg/projectdiscovery) on Discord.

Happy hacking! ⚙️
