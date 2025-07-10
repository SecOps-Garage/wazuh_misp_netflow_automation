

# CTI Automation with Wazuh, MISP, and Netflow

## Project Background

Modern enterprise networks and data centers have grown in both size and complexity. With hundreds of applications running on distributed Virtual Machines (VMs) and cloud platforms, the attack surface is large and constantly changing. This presents several key challenges for security teams:

- **Challenge 1: Siloed Detection**  
  Security tools like Wazuh can detect suspicious activity on individual machines or applications, but these alerts are often isolated. As a result, it’s hard to spot patterns—such as the same attacker targeting multiple systems across the network.

- **Challenge 2: Slow Threat Intelligence Sharing**  
  When Indicators of Compromise (IOCs)—like malicious IP addresses—are detected, they need to be shared quickly with all relevant teams and systems. Delays can give attackers more time to move laterally or attack other assets.

- **Challenge 3: Limited Network Visibility**  
  Even if an attacker is identified on one system, it's difficult to know if they have tried to access or have already compromised other systems without comprehensive network traffic analysis.

### Solution Overview
---

This project solves these problems by automating the collection and sharing of IOCs, and by correlating endpoint detections with network activity:

![image](https://github.com/user-attachments/assets/e574d1f5-a232-47e4-8b45-615fa072f3e1)


1. **Automated IOC Extraction:**  
   When Wazuh detects suspicious activity, the relevant IOCs (like attacker IPs) are automatically extracted.

2. **Real-Time Sharing with MISP:**  
   These IOCs are immediately shared with MISP (Malware Information Sharing Platform), so threat intelligence is updated in real time and available to all connected teams and tools.

3. **Network Correlation via Elasticsearch:**  
   The solution checks internal Netflow logs (stored in Elasticsearch) to see if the attacker IP has tried to access other systems, helping to identify broader attack campaigns or lateral movement.

This integrated approach enables faster incident detection, better visibility, and more effective response.

---

## Solution Architecture

Below is a high-level diagram showing how the system works:

```mermaid
flowchart LR
    subgraph Detection & Collection
        Wazuh[Wazuh: Security Logs & Alerts]
    end
    subgraph Automation & Correlation
        Script[Automation Script]
    end
    subgraph Threat Intelligence Sharing
        MISP[MISP: Threat Intelligence Platform]
    end
    subgraph Network Analysis
        ES[Elasticsearch: Netflow Logs]
    end

    Wazuh -- Extract IOCs --> Script
    Script -- Push IOCs --> MISP
    Script -- Query IPs --> ES
    ES -- Return Matches --> Script
```

## Required Components

Ensure the following are in place before setup:

- **Wazuh Manager:** Collects/analyzes security events; alerts are stored as indices in Elasticsearch.
- **MISP Instance:** Receives IOCs from Wazuh alerts for real-time threat intelligence sharing.
- **Netflow Log Collection in Elasticsearch:** Stores Netflow logs to cross-verify attacker IPs.
---

## Automated IOC Extraction and MISP Integration

The core of this project is the [`wazuh_to_misp_ingest.py`](wazuh_to_misp_ingest.py) script, which automates the extraction of Indicators of Compromise (IOCs) from Wazuh alerts stored in Elasticsearch and shares them as structured events with your MISP instance.

### How the Script Works

- **Configurable Connections:**  
  The script connects securely to your Elasticsearch (where Wazuh alerts are stored) and your MISP instance using API keys and credentials.

- **Smart Tracking:**  
  It keeps track of which events have already been pushed using local files, ensuring only new and unique IOCs are sent to MISP.

- **Alert Query & Grouping:**  
  - Fetches recent alerts from Wazuh indices in Elasticsearch, focusing on web-access logs with attacker IPs, URLs, and MITRE ATT&CK context.
  - Groups alerts by source IP, collecting all URLs, MITRE tactics/techniques, and geolocation info for each attacker.

- **Event Creation in MISP:**  
  - For every new attacker IP (not previously pushed), it creates a MISP event with:
    - Source IP as `ip-src`
    - All suspicious/malicious URLs as `url` attributes
    - MITRE tactic & technique, geo data, and relevant tags
  - Publishes the event to MISP via its API

- **Runs Automatically:**  
  By default, the script runs in a loop, updating MISP every 15 minutes with any new threats detected.

### Example Configuration

Edit the script variables  [`wazuh_to_misp_ingest.py`](wazuh_to_misp_ingest.py) or set environment variables as follows:

```env
MISP_URL=https://your-misp-server-url
MISP_KEY=YOUR_MISP_API_KEY
ES_HOST=https://your-elasticsearch-host:9200
ES_USER=your-es-username
ES_PASS=your-es-password
```

### Usage

To start the automation, simply run:

```bash
python3 wazuh_to_misp_ingest.py
```

The script will continue running, periodically checking for new alerts and pushing them to MISP.

### Workflow Diagram
```mermaid
flowchart TD
    Wazuh["Wazuh Alerts (Elasticsearch)"]
    Script["wazuh_to_misp_ingest.py"]
    MISP["MISP Server"]

    Wazuh -->|Fetch alerts| Script
    Script -->|Group, enrich, deduplicate| Script
    Script -->|Push as event| MISP
    Script -->|Track UUID and timestamps| Script
    Script -->|Repeat every 15 min| Script
```
### Security Note

- In production, enable SSL certificate verification and restrict access to the script.

---

This script is the core bridge between detection in Wazuh and actionable sharing in MISP, enabling real-time, automated threat intelligence across your network.


---

## Proof-of-Concept (POC) Steps

This section demonstrates the end-to-end workflow of IOC extraction and sharing, with key screenshots from each stage:

### 1. Detection in Wazuh Dashboard

*Wazuh dashboard displaying detections from web access logs (e.g., suspicious requests, attacker IPs, MITRE mapping).*
![image](https://github.com/user-attachments/assets/1b13ed64-36b1-42ba-9cb9-696d994d2213)

---

### 2. Execution of the Script

*Running the `wazuh_to_misp_ingest.py` script and its output in the terminal, showing successful IOC extraction and event pushes to MISP.*

![image](https://github.com/user-attachments/assets/cb1d878a-54a3-400a-b550-94bc40bad2bd)

---

### 3. Event Creation in MISP Portal

*Viewing the newly created event in the MISP portal, with IOCs, attributes, tags, and associated threat context.*

![image](https://github.com/user-attachments/assets/91eab30e-da6a-47be-b7d2-3307dc344d4e)


---

![image](https://github.com/user-attachments/assets/1aace8a4-93ac-4c55-9589-90ebee934810)

---


## Sharing MISP Events with the Community

After creating events in MISP, you can leverage its sharing features to distribute threat intelligence with your security community, partners, or other organizations.

### Step-by-Step: Sharing MISP Events

1. **Review and Tag Your Event**
   - Open your event in MISP.
   - Add relevant tags (e.g., TLP, sector, threat type) to classify the event for consumers.
   - _Example Screenshot:_
    ![image](https://github.com/user-attachments/assets/fa09d981-0769-46ae-8d9e-8fdebf6cd0ff)

   - publish the event

     ![image](https://github.com/user-attachments/assets/1f243ff8-288c-4ca5-a4ef-6a3a8848dd7e)



  

2. **Set Distribution Level**
   - In the event editor, set the **Distribution** field:
     - Your Organization Only
     - This Community Only
     - Connected Communities
     - All Communities
   - Selecting a broader level increases event reach.
   - _Example Screenshot:_  
     ![Distribution Settings](path/to/misp_distribution.png)

3. **Sync with Partner MISP Instances**
   - Go to **Administration > List Servers** and add a new server for peer sharing.
   - Configure sync direction (Push/Pull/Both).
   - Ensure your event’s distribution and tags allow it to be shared with the desired partner.
   - _Example Screenshot:_  
     ![MISP Sync Setup](path/to/misp_sync.png)

4. **Manual Export (Optional)**
   - Events can be exported via the **Export** tab in STIX, JSON, CSV, or other formats.
   - Share exports by email, API, or other means.
   - _Example Screenshot:_  
     ![MISP Export](path/to/misp_export.png)

5. **Verify Sharing**
   - Check partner MISP instance or recipient to confirm successful sharing.
   - _Example Screenshot:_  
     ![MISP Event in Peer Instance](path/to/peer_misp_event.png)

---

## Leveraging MISP IOCs with Netflow via Elasticsearch

Integrate MISP IOCs into your network monitoring pipeline to detect malicious activity using Netflow logs and Elasticsearch.
 


> **Note:**  
> For this demonstration, our SIEM is already configured to collect Netflow logs from one of the perimeter devices.

### Step 1: Ingest MISP IOCs into Elasticsearch Using Filebeat Threat Intel Module

---

1. **Enable the Filebeat Threat Intel Module**
   
   Enable the module using the following command:
   ```bash
   sudo filebeat modules enable threatintel
   ```

---

Then, edit the threatintel.yml file in the /etc/filebeat/modules.d/ directory with your own misp instance ip/url and API

#### Example: `threatintel.yml` for Filebeat MISP Integration

```yaml
misp:
  enabled: true

  # Input used for ingesting threat intel data, defaults to JSON.
  var.input: httpjson

  # The URL of the MISP instance, should end with "/events/restSearch".
  var.url: https://your-misp-server-url/events/restSearch

  # The authentication token used to contact the MISP API. Found in your MISP user account settings.
  var.api_token: YOUR_MISP_API_TOKEN

  # Configures the type of SSL verification done. Use 'none' for self-signed certs (not recommended for production).
  var.ssl.verification_mode: none

  # Optional filters for the API to filter out results. See Filebeat module docs for details.
  #var.filters:
  #  - threat_level: [4, 5]
  #  - to_ids: true

  # How far back to look on first startup, in hours.
  var.first_interval: 300h

  # The interval to poll the API for updates.
```

> **Note:**  
> - Replace `https://your-misp-server-url` and `YOUR_MISP_API_TOKEN` with your actual details during deployment, but do **not** commit these to public repos.
> - For production, set `ssl.verification_mode` to `full` and use valid certificates.



2. **Configure Output to Elasticsearch**
   - Ensure Filebeat outputs to your Elasticsearch cluster:
     ```yaml
     output.elasticsearch:
       hosts: ["https://your-es-host:9200"]
       username: "your-es-username"
       password: "your-es-password"
       ssl.verification_mode: none   # Use 'full' in production
     ```

3. **Start Filebeat**
   - On your server, run:
     ```bash
     sudo filebeat modules enable threatintel
     sudo filebeat setup
     sudo systemctl start filebeat
     sudo filebeat setup -e
     ```
   - Confirm that Filebeat is running and logs are being sent to Elasticsearch.
   - _Example Screenshot:_  
     ![image](https://github.com/user-attachments/assets/79b4a6da-16e0-4c49-8be0-a62962a69ea6)


4. **Verify IOCs in Elasticsearch**
   - In Kibana, search the `filebeat-*` index for recent MISP indicators.
   - _Example Screenshot:_  
     ![image](https://github.com/user-attachments/assets/784c3325-9068-4ef7-9b96-78235a64930c)


---

### Step 2: Create Indicator Match Security Rules in Elasticsearch (Kibana)

1. **Go to Security > Rules in Kibana**
   - Navigate to **Security > Detection rules** in Kibana.
   - Click **Create rule** > **Indicator match rule**.

2. **Configure the Rule**
   - **Name:** e.g., "Netflow matches with MISP IOCs"
   - **Index patterns:** (e.g., `netflow-*`)
   - **Indicator index patterns:** (e.g., `filebeat-*`)
   - **Indicator mapping:**
     - Match `source.ip` or `destination.ip` in Netflow data to `threat.indicator.ip` from threat intel.
   - _Example Screenshot:_  
     ![Indicator Match Rule Setup](path/to/indicator_match_rule.png)

3. **Set Rule Actions**
   - Choose actions: send alerts, email, Slack, etc.
   - Optionally, add severity and tags.

4. **Save and Enable the Rule**
   - Save and enable your rule.
   - _Example Screenshot:_  
     ![Enabled Rule](path/to/enabled_rule.png)

5. **Test the Setup**
   - Simulate or use real traffic to trigger a match.
   - Review alerts in Kibana.
   - _Example Screenshot:_  
     ![Triggered Alert](path/to/alert_result.png)

---

**Replace the screenshot paths with your own images to illustrate each step.**  
If you need example configuration files or troubleshooting notes for these steps, let me know!

## Additional Notes

- Tested with **Elasticsearch 7.17.13** and **Wazuh App version 4.53**.
- For newer Wazuh versions, please review/adjust configurations as needed.

---

## Contributing / Support

_Explain how users can contribute or get help._

---

## License

_Provide your license information here (e.g., MIT, Apache 2.0, etc.)._

---

**Fill in the code, configuration, and diagram sections as needed. All previous images are preserved as requested.**
