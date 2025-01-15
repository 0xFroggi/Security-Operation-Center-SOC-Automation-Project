# Security-Operation-Center-SOC-Automation-Project

### SOC Automation Lab Report

#### **1. Introduction**
This report details the setup and implementation of a Security Operations Center (SOC) automation lab. The objective of this lab is to automate workflows for detecting, responding, and alerting on security threats, such as the usage of Mimikatz. The tools used in this project include:

- **Wazuh**: Open-source security monitoring platform for log collection and analysis.
- **TheHive**: Incident response and alert management.
- **Sysmon**: Windows event monitoring tool for detailed logging.
- **Shuffle**: Security Orchestration, Automation, and Response (SOAR) platform.
- **VirusTotal**: Online file and hash scanning tool for malware detection.

This project demonstrates how these tools work together to create an automated SOC workflow for threat detection and response.

**SOC Automation Workflow Diagram:**
![SOC Automation Diagram](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/SOC%20Automation%20Diagram.png)

---

#### **2. Environment Setup**

**Tools and Architecture:**
- **Wazuh**: Acts as the central log and alerting system.
- **TheHive**: Manages incident response and stores alerts from Wazuh.
- **Sysmon**: Monitors and logs detailed system events, including process execution.
- **Shuffle**: Automates alert workflows and integration with third-party tools like VirusTotal.

**Login Screens:**
- **Wazuh Login**:  
  ![Wazuh Login Interface](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/wazuh%20login.png)
- **TheHive Login**:  
  ![TheHive Login Interface](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/hive%20login.png)
- **Sysmon Log Generation**:  
  ![Sysmon Log Generation](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/sysmon%20filter%20wazuh.png)

---

#### **3. Configurations**

**Wazuh Configuration:**
- Sysmon logs are routed to Wazuh for analysis.  
  ![Sysmon Logs Configuration](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/wazuh%20agent%20sysmon%20logs%20to%20wazuh.png)

**Custom Rules:**
- A custom rule was created in Wazuh to detect Mimikatz execution based on specific file names and patterns.  
  ![Custom Rule for Mimikatz Detection](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/custom%20rule%20for%20mimi%20in%20wazuh.png)
- **Rule Validation in Wazuh Dashboard**:  
  ![Wazuh Dashboard Validation](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/wazuh%20dash%20mimi%20rule%20works%202.png)

**Shuffle Integration:**
- Webhook integration between Wazuh and Shuffle was configured to automate responses to detected threats.  
  ![Shuffle Integration](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/connecting%20wazuh%20to%20shuffle%20ossec%20file.png)

**Regex Parsing for SHA256:**
- A regex rule was configured in Shuffle to parse SHA256 hashes from Wazuh alerts.  
  ![Regex Configuration](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/hash%20regex%20config%20shuffle.png)
- **Parsed Hash in Shuffle**:  
  ![Hash Parsed](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/hash%20parsed.png)

---

#### **4. Workflow Automation**

**Workflow Example:**
- A workflow in Shuffle sends email alerts whenever Wazuh detects Mimikatz.  
  ![Workflow in Shuffle](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/shuffle%20email%20dash.png)

**Execution Argument Details:**
- Details of the Shuffle workflow execution when an alert is triggered.  
- **Alert Received**:  
  ![Alert Received in Shuffle](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/shuffle%20alert%20received%20info.png)

---

#### **5. Detection and Response**

**Mimikatz Detection:**
- **Wazuh Dashboard**:  
  Displays detections of Mimikatz activity.  
  ![Wazuh Detection](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/wazuh%20dash%20mimi.png)
- **Sysmon Logs**:  
  Logs generated in Sysmon showing process execution details.  
  ![Sysmon Logs](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/sysmon%20mimi%20log%20generation.png)

**Alert Management in TheHive:**
- Alerts generated in Wazuh are sent to TheHive for incident response.  
  - **Alert in TheHive**:  
    ![TheHive Alert](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/hive%20alert2.png)
  - **Alert JSON Structure**:  
    ![Alert JSON](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/alert%20json%20hive.png)


---

#### **6. Reporting**

**VirusTotal Lookup:**
- The SHA256 hash of the detected file is checked against VirusTotal.  
  ![VirusTotal Results](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/virus%20total%20first%20result.png)

**Email Notification:**
- An email notification is sent via Shuffle when Mimikatz is detected.  
  ![Email Notification](https://github.com/0xFroggi/Security-Operation-Center-SOC-Automation-Project/blob/main/images/email%20recieved.png)


---

#### **7. Conclusion**

The SOC automation lab demonstrates the importance of integrating multiple tools to automate the detection and response to security threats. By combining Wazuh, TheHive, Sysmon, Shuffle, and VirusTotal, this lab achieves:
- Reduced response times to detected threats.
- Automated reporting and alerting mechanisms.
- Improved SOC efficiency through workflow automation.

The implementation of custom rules, automated workflows, and integration with external threat intelligence platforms ensures a robust and scalable approach to SOC operations.
