# **CSIRT Tools**

## **Overview**

**CSIRT Tools** is a set of incident response scripts designed for security professionals and system administrators. It helps in performing various checks and analysis on a system to identify potential security issues and anomalies. The tool provides functionality to check system information, network communication, user details, and logs for suspicious activities.

## **Features**

- **System Version Information**
- **Process, Service, and Apps**
- **Network Communication Analysis**
- **User, Crojobs, History**
- **File Modification Search**
- **Writable Directories/Files/SUID**
- **Backdoor Files Detection**
- **Access Log Analysis**
- **Authentication Log Analysis**
- **System Log Analysis**

## **Installation**

To use CSIRT Tools, you need to have a Linux operating system with bash installed. The script is designed to be run on systems with common tools available.

```
1. git clone https://github.com/yogasatriautama/csirt-tools.git
2. chmod +x csirt_tools.sh
3. sudo ./csirt_tools.sh | tee -a result.txt
```

## **Tested on:**
- Ubuntu
- Debian
