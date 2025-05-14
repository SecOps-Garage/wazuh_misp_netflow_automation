# **CTI automation with Wazuh,MISP and Netflow**

## **Project Background**
In large enterprise networks or data centers, especially those with hundreds of applications hosted across distributed Virtual Machines (VMs), it is not uncommon for the same attacker to attempt web-based attacks across multiple VMs. Given the scale of such networks, some critical VMs might not have proper security agents installed due to resource constraints or operational challenges. Moreover, north-south traffic (traffic between the internal network and external networks) might not always be monitored by an Intrusion Detection System (IDS), or worse, it might be evading existing firewall protections.

In such environments, detecting and responding to web-based attacks becomes a major challenge, especially when the attacker is executing coordinated attacks across multiple VMs or applications. Without proper visibility into the traffic and events from these VMs, enterprises are left vulnerable to widespread attacks that could go unnoticed, leading to data breaches or compromises.

To address these issues, the proposed solution automates the process of extracting Indicators of Compromise (IOCs) from Wazuh logs, a powerful security monitoring tool, and pushing them to MISP (Malware Information Sharing Platform). The solution not only extracts the web attack data from Wazuh but also enhances the detection process by cross-verifying attacker IPs with Netflow traffic data stored in Elasticsearch. This helps identify malicious activity that might have been missed by traditional security measures and ensures a proactive approach to threat intelligence sharing.

In essence, the solution provides continuous monitoring and incident response capabilities for detecting web attacks, even in the absence of direct agent installation or when facing challenges such as network misconfigurations and firewall evasion. It creates an automated flow of threat data from Wazuh logs to MISP, ensuring that critical attack data is shared in real-time, enhancing overall security posture and facilitating quicker responses to emerging threats.

![image](https://github.com/user-attachments/assets/db9769b4-79e8-4d4a-9399-0cbc0fe5de00)



## **Project Overview**

This project automates the extraction and sharing of **Indicators of Compromise (IOCs)** from **Wazuh logs** to **MISP (Malware Information Sharing Platform)**. It enables real-time sharing of threat intelligence, helping in incident response by automatically pushing web attack data from **Wazuh** into **MISP**. The solution also cross-verifies attacker IPs with internal **Netflow traffic** in **Elasticsearch**, which can help identify additional suspicious activity.

![image](https://github.com/user-attachments/assets/e987325b-fdb5-4521-928f-fc069a4b03c0)



### **What Does the Script Do?**
1. **Fetches Wazuh Alerts**: The script queries **Wazuh** logs stored in **Elasticsearch** for web attack alerts, filtering by fields such as **source IP (`srcip`)**, **URLs**, and **MITRE TTPs**.
2. **Processes and Extracts IOCs**: It processes the alerts to extract valuable **Indicators of Compromise (IOCs)** such as:
   - **Attacker IP** (from `srcip` field)
   - **Suspicious URLs** (from `url` field) – Changed from "Malicious URLs"
   - **MITRE Tactics, Techniques, and Procedures (TTPs)**
   - **Geo-location** (from the `GeoLocation` field)
3. **Pushes IOCs to MISP**: The script then pushes these IOCs as **events** to **MISP**. It creates new events only if the **MITRE TTP ID** is not already present in MISP, preventing duplicates.
4. **Tracks Processed Events**: It keeps track of processed events using **UUIDs** and saves the last ingest time to ensure that only new alerts are processed in subsequent runs.

### **Key Benefits**
- **Real-Time Threat Intelligence**: Pushes IOCs to MISP as soon as they are detected in Wazuh logs, enabling rapid response.
- **Automated Incident Response**: Reduces manual intervention by automatically sharing IOCs.
- **Enhanced Detection**: Cross-references IOCs with internal **Netflow traffic** using **Elasticsearch** to detect further attacks.

---

## **Installation and Setup**

### **Step 1: Clone the Repository**

1. **Go to GitHub**: 
   - Navigate to your GitHub account and create a repository called **`wazuh_to_misp_integration`**.
2. **Clone the Repository**:
   - Open your terminal (command prompt) and run the following command to clone the repository:
     ```bash
     git clone https://github.com/YOUR_USERNAME/wazuh_to_misp_integration.git
     cd wazuh_to_misp_integration
     ```

---

### **Step 2: Install the Required Python Packages**

You need some Python libraries to run the script. These libraries are listed in the `requirements.txt` file.

1. **Create the `requirements.txt` file** by running:
   ```bash
   echo -e "requests\nelasticsearch\nurllib3" > requirements.txt

