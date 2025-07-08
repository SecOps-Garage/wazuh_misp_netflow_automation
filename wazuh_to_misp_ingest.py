import json
import requests
import urllib3
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from collections import defaultdict
import os
import time

# === Suppress SSL Warnings ===
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === MISP Server Config ===
MISP_URL = "https://your-misp-server-url"  # Replace with your MISP instance URL
MISP_KEY = "YOUR_MISP_API_KEY"             # Replace with your MISP API key
HEADERS = {
    'Authorization': MISP_KEY,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# === Elasticsearch Config ===
ES_HOST = "https://your-elasticsearch-host:9200"  # Replace with your Elasticsearch host
ES_USER = "your-es-username"                      # Replace with your Elasticsearch username
ES_PASS = "your-es-password"                      # Replace with your Elasticsearch password

# === Files for tracking ===
UUID_FILE = "event_uuids.json"
TIME_FILE = "last_ingest_time.json"

# === MITRE Tactics (Tag Only) ===
TACTIC_TAGS = {
    "Reconnaissance": "MITRE Tactic: Reconnaissance",
    "Resource Development": "MITRE Tactic: Resource Development",
    "Initial Access": "MITRE Tactic: Initial Access",
    "Execution": "MITRE Tactic: Execution",
    "Persistence": "MITRE Tactic: Persistence",
    "Privilege Escalation": "MITRE Tactic: Privilege Escalation",
    "Defense Evasion": "MITRE Tactic: Defense Evasion",
    "Credential Access": "MITRE Tactic: Credential Access",
    "Discovery": "MITRE Tactic: Discovery",
    "Lateral Movement": "MITRE Tactic: Lateral Movement",
    "Collection": "MITRE Tactic: Collection",
    "Command and Control": "MITRE Tactic: Command and Control",
    "Exfiltration": "MITRE Tactic: Exfiltration",
    "Impact": "MITRE Tactic: Impact"
}

# === Load/Save UUIDs ===
def load_existing_uuids():
    try:
        with open(UUID_FILE, "r") as f:
            data = f.read().strip()
            if data:
                return json.loads(data)
            else:
                return []
    except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
        print(f"[INFO] Error loading UUID file: {e}, initializing with empty list.")
        return []

def save_new_uuid(uuid):
    uuids = load_existing_uuids()
    if uuid not in uuids:
        uuids.append(uuid)
        with open(UUID_FILE, "w") as f:
            json.dump(uuids, f)

# === Load/Save Last Ingest Time ===
def load_last_ingest_time():
    try:
        with open(TIME_FILE, "r") as f:
            data = json.load(f)
            return data.get("last_ingest", (datetime.utcnow() - timedelta(hours=24)).isoformat())
    except (FileNotFoundError, KeyError, json.decoder.JSONDecodeError):
        return (datetime.utcnow() - timedelta(hours=24)).isoformat()

def save_last_ingest_time(latest_ts):
    with open(TIME_FILE, "w") as f:
        json.dump({"last_ingest": latest_ts}, f)

# === Connect to Elasticsearch ===
es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASS), verify_certs=False)

# === Fetch Existing MISP Event UUIDs ===
def fetch_existing_misp_event_uuids():
    url = f"{MISP_URL}/events"
    try:
        response = requests.get(url, headers=HEADERS, verify=False)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict) and 'events' in data:
                return [event['uuid'] for event in data['events'] if 'uuid' in event]
            else:
                return []
        else:
            print(f"[ERROR] MISP Error: {response.status_code} -> {response.text}")
            return []
    except Exception as e:
        print(f"[ERROR] Exception fetching MISP events: {e}")
        return []

# === Prepare Query for Wazuh Elasticsearch ===
def process_and_push_events():
    # Check if it's the first time running the script or not
    first_run = check_first_run()

    # If it's the first run, set the last ingest time to the current time
    if first_run:
        print("[INFO] First time running the script. Fetching all events.")
        last_ingest_time = (datetime.utcnow() - timedelta(days=1)).isoformat()  # Fetch last 24 hours of events
    else:
        last_ingest_time = load_last_ingest_time()  # Get the last ingest time for subsequent runs
        print(f"[INFO] Using last ingest time: {last_ingest_time}")

    # We broaden the time range for querying all possible alerts in case of missing events
    time_from = last_ingest_time if last_ingest_time else (datetime.utcnow() - timedelta(days=1)).isoformat()  # Ensure last_ingest_time is valid
    time_to = datetime.utcnow().isoformat()

    query = {
        "bool": {
            "must": [
                {"match": {"decoder.name": "web-accesslog"}},
                {"exists": {"field": "data.srcip"}},
                {"exists": {"field": "data.url"}},
                {"exists": {"field": "rule.mitre.id"}},
                {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}}
            ]
        }
    }

    # === Execute Search on Wazuh Elasticsearch ===
    response = es.search(index="wazuh-alerts-*", query=query, size=5000)
    hits = response['hits']['hits']

    if not hits:
        print("[INFO] No new alerts found. Exiting script.")
        return

    # === Process and Group Alerts by IP ===
    grouped = defaultdict(lambda: {
        "urls": set(), "tactic": None, "technique": None,
        "mitre_id": None, "geo": None
    })

    latest_ts_seen = last_ingest_time  # Initialize to last ingest time

    # Process each hit
    for hit in hits:
        alert = hit['_source']
        timestamp = alert.get("@timestamp")

        # Ensure timestamp is in the correct format for comparison
        if timestamp and latest_ts_seen and timestamp > latest_ts_seen:
            latest_ts_seen = timestamp

        ip = alert.get("data", {}).get("srcip")
        url = alert.get("data", {}).get("url")
        mitre = alert.get("rule", {}).get("mitre", {})
        tactic = mitre.get("tactic", [None])[0]
        technique = mitre.get("technique", [None])[0]
        mitre_id = mitre.get("id", [None])[0]
        geo = alert.get("GeoLocation", {})

        if geo:
            geo_info = ", ".join(filter(None, [
                geo.get("city_name"),
                geo.get("region_name"),
                geo.get("country_name")
            ]))
        else:
            geo_info = None

        if ip and url and mitre_id:
            grouped[ip]["urls"].add(url)
            grouped[ip]["tactic"] = tactic
            grouped[ip]["technique"] = technique
            grouped[ip]["mitre_id"] = mitre_id
            grouped[ip]["geo"] = geo_info

    # === Compare UUIDs and Push New Events to MISP ===
    existing_uuids = load_existing_uuids()
    misp_uuids = fetch_existing_misp_event_uuids()

    missing_uuids = []
    for ip, data in grouped.items():
        if data["mitre_id"] not in misp_uuids:
            missing_uuids.append(data["mitre_id"])

    # Push missing events to MISP
    for ip, data in grouped.items():
        if data["mitre_id"] in missing_uuids:
            event = {
                "Event": {
                    "info": f"Web attack from {ip} with MITRE TTP",
                    "published": True,
                    "distribution": 1,
                    "Attribute": [],
                    "Tag": [{"name": "attack-type: web-accesslog"}]
                }
            }

            # Add Source IP
            event["Event"]["Attribute"].append({
                "type": "ip-src", "category": "Network activity",
                "to_ids": True, "value": ip, "comment": "Attacker source IP"
            })

            # Add URLs (Changed from "Malicious request URL" to "Suspicious request URL")
            for url in sorted(data["urls"]):
                event["Event"]["Attribute"].append({
                    "type": "url", "category": "Payload delivery",
                    "to_ids": True, "value": url, "comment": "Suspicious request URL"  # Changed comment here
                })

            # Add GeoIP Info
            if data["geo"]:
                event["Event"]["Attribute"].append({
                    "type": "text", "category": "External analysis",
                    "value": data["geo"],
                    "comment": "Source GeoIP"
                })

            # Add MITRE TTP
            if data["tactic"] and data["technique"]:
                event["Event"]["Attribute"].append({
                    "type": "text", "category": "External analysis",
                    "value": f"{data['tactic']} - {data['technique']}",
                    "comment": "MITRE TTP"
                })
                if data["tactic"] in TACTIC_TAGS:
                    event["Event"]["Tag"].append({"name": TACTIC_TAGS[data["tactic"]]})

            try:
                res = requests.post(f"{MISP_URL}/events/add", headers=HEADERS, json=event, verify=False, timeout=180)
                if res.status_code == 200:
                    uuid = res.json()['Event']['uuid']
                    if uuid not in existing_uuids:
                        print(f"[✓] Event created for {ip} → MISP ID: {res.json()['Event']['id']}")
                        save_new_uuid(uuid)
                    else:
                        print(f"[=] Duplicate event skipped for {ip}")
                else:
                    print(f"[✗] MISP Error: {res.status_code} → {res.text}")
            except Exception as e:
                print(f"[!] Exception for {ip}: {e}")

    # Save the latest timestamp for next run
    save_last_ingest_time(latest_ts_seen)

# Check if it is the first run or not
def check_first_run():
    if os.path.exists(TIME_FILE):
        return False
    else:
        return True

# Run the script periodically every 15 minutes
if __name__ == "__main__":
    while True:
        print("[INFO] Running periodic task...")
        process_and_push_events()
        print("[INFO] Sleeping for 15 minutes...")
        time.sleep(900)  # Sleep for 15 minutes
