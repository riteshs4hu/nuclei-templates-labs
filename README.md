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
git clone https://github.com/yourusername/Nuclei-Templates-Labs.git
cd Nuclei-Templates-Labs
```

### 2. Install dependencies
Ensure you have **Docker** and **Docker Compose** installed.

```bash
# Install Docker (if not installed)
sudo apt update && sudo apt install docker.io -y

# Install Docker Compose
sudo apt install docker-compose -y
```

### 3. Launch the vulnerable environment
```bash
docker-compose up -d
```
This will spin up all the vulnerable services needed for testing.

### 4. Install Nuclei
If you haven’t installed Nuclei yet, run:
```bash
# Install Nuclei
curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep browser_download_url | grep linux_amd64.zip | cut -d '"' -f 4 | wget -i -
unzip nuclei-linux-amd64.zip
chmod +x nuclei
sudo mv nuclei /usr/local/bin/
```
Verify the installation:
```bash
nuclei -version
```

### 5. Run Nuclei against the lab environments
```bash
nuclei -t templates/ -u http://<LAB_IP>:<PORT>
```
Replace `<LAB_IP>` and `<PORT>` with the appropriate values for the running environment.

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