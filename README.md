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
![SOC Automation Diagram](placeholder-url-soc-automation-diagram.png)

---

#### **2. Environment Setup**

**Tools and Architecture:**
- **Wazuh**: Acts as the central log and alerting system.
- **TheHive**: Manages incident response and stores alerts from Wazuh.
- **Sysmon**: Monitors and logs detailed system events, including process execution.
- **Shuffle**: Automates alert workflows and integration with third-party tools like VirusTotal.

**Login Screens:**
- **Wazuh Login**:  
  ![Wazuh Login Interface](placeholder-url-wazuh-login.png)
- **TheHive Login**:  
  ![TheHive Login Interface](placeholder-url-hive-login.png)
- **Sysmon Log Generation**:  
  ![Sysmon Log Generation](placeholder-url-sysmon-mimi-log-generation.png)

---

#### **3. Configurations**

**Wazuh Configuration:**
- Sysmon logs are routed to Wazuh for analysis.  
  ![Sysmon Logs Configuration](placeholder-url-wazuh-agent-sysmon-logs.png)

**Custom Rules:**
- A custom rule was created in Wazuh to detect Mimikatz execution based on specific file names and patterns.  
  ![Custom Rule for Mimikatz Detection](placeholder-url-custom-rule.png)
- **Rule Validation in Wazuh Dashboard**:  
  ![Wazuh Dashboard Validation](placeholder-url-wazuh-dash-mimi-rule-works.png)

**Shuffle Integration:**
- Webhook integration between Wazuh and Shuffle was configured to automate responses to detected threats.  
  ![Shuffle Integration](placeholder-url-wazuh-shuffle-integration.png)

**Regex Parsing for SHA256:**
- A regex rule was configured in Shuffle to parse SHA256 hashes from Wazuh alerts.  
  ![Regex Configuration](placeholder-url-regex-configuration.png)
- **Parsed Hash in Shuffle**:  
  ![Hash Parsed](placeholder-url-hash-parsed.png)

---

#### **4. Workflow Automation**

**Workflow Example:**
- A workflow in Shuffle sends email alerts whenever Wazuh detects Mimikatz.  
  ![Workflow in Shuffle](placeholder-url-workflow.png)

**Execution Argument Details:**
- Details of the Shuffle workflow execution when an alert is triggered.  
  ![Execution Argument Details](placeholder-url-execution-details.png)
- **Alert Received**:  
  ![Alert Received in Shuffle](placeholder-url-shuffle-alert-received-info.png)

---

#### **5. Detection and Response**

**Mimikatz Detection:**
- **Wazuh Dashboard**:  
  Displays detections of Mimikatz activity.  
  ![Wazuh Detection](placeholder-url-wazuh-detection.png)
- **Sysmon Logs**:  
  Logs generated in Sysmon showing process execution details.  
  ![Sysmon Logs](placeholder-url-sysmon-logs.png)

**Alert Management in TheHive:**
- Alerts generated in Wazuh are sent to TheHive for incident response.  
  - **Alert in TheHive**:  
    ![TheHive Alert](placeholder-url-hive-alert.png)
  - **Alert JSON Structure**:  
    ![Alert JSON](placeholder-url-alert-json.png)

**Wazuh Archive Logs:**
- Logs generated and stored for additional validation.  
  ![Wazuh Archive Logs](placeholder-url-wazuh-server-mimi-archives.png)

---

#### **6. Reporting**

**VirusTotal Lookup:**
- The SHA256 hash of the detected file is checked against VirusTotal.  
  ![VirusTotal Results](placeholder-url-virustotal-results.png)

**Email Notification:**
- An email notification is sent via Shuffle when Mimikatz is detected.  
  ![Email Notification](placeholder-url-email-notification.png)
- **Detailed Workflow for Email Alerts**:  
  ![Workflow for Email Alerts](placeholder-url-shuffle-email-dash.png)

---

#### **7. Conclusion**

The SOC automation lab demonstrates the importance of integrating multiple tools to automate the detection and response to security threats. By combining Wazuh, TheHive, Sysmon, Shuffle, and VirusTotal, this lab achieves:
- Reduced response times to detected threats.
- Automated reporting and alerting mechanisms.
- Improved SOC efficiency through workflow automation.

The implementation of custom rules, automated workflows, and integration with external threat intelligence platforms ensures a robust and scalable approach to SOC operations.
