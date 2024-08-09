# **CSIRT Tools**

## **Overview**

**CSIRT Tools** is a set of incident response scripts designed for security professionals and system administrators. It helps in performing various checks and analysis on a system to identify potential security issues and anomalies. The tool provides functionality to check system information, network communication, user details, and logs for suspicious activities.

## **Features**

- **System Version Information**
- **Process, Service, and Startup Information**
- **Network Communication Analysis**
- **User Information**
- **File Modification Search**
- **Writable Directories/Files/SUID**
- **Backdoor Files Detection**
- **Access Log Analysis**
- **Authentication Log Analysis**

## **Installation**

To use CSIRT Tools, you need to have a Linux operating system with bash installed. The script is designed to be run on systems with common tools available.

### **Steps**

1. **Clone the Repository**

   git clone https://github.com/yogasatriautama/csirt-tools.git

2. **Make the Script Executable**

   chmod +x csirt_tools.sh

3. **Usage**

   sudo ./csirt_tools.sh

## **Access Log and Auth Log Paths**
The script is designed to handle different log paths based on common conventions. If logs are located in non-standard directories, you may need to adjust the script accordingly.

## **Contributing**
Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## **License**
This project is licensed under the MIT License - see the LICENSE file for details.
