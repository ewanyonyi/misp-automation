import pandas as pd
import json
import urllib3
from pymisp import PyMISP, MISPEvent, MISPObject, MISPAttribute

# Suppress SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from settings import MISP_URL, MISP_KEY, MISP_VERIFYCERT, CSV_FILE

# --- MISP Initialization ---
try:
    misp = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT, 'json')
except Exception as e:
    print(f"Error initializing PyMISP: {e}")
    exit()

# Build case-insensitive lookups from the live MISP instance
_misp_categories = {cat.lower(): cat for cat in misp.describe_types_remote['category_type_mappings'].keys()}
_misp_types = {t.lower(): t for t in misp.describe_types_remote['types']}

# Known typos in the CSV -> correct MISP type
_type_typo_fixes = {
    'ip-sre': 'ip-src',
}

def resolve_category(csv_category) -> str:
    """Resolve a CSV category name to the exact case MISP expects."""
    if not isinstance(csv_category, str):
        return 'Other'
    normalised = csv_category.strip().lower()
    if normalised in _misp_categories:
        return _misp_categories[normalised]
    return csv_category.strip()

def resolve_type(csv_type) -> str:
    """Correct known typos and normalise MISP attribute types from the CSV."""
    if not isinstance(csv_type, str):
        return 'other'
    cleaned = csv_type.strip()
    corrected = _type_typo_fixes.get(cleaned.lower(), cleaned)
    return _misp_types.get(corrected.lower(), corrected)

# --- Utility Functions ---

def create_event(row):
    """Creates a new MISP Event object based on the first row attributes."""
    event = MISPEvent()
    
    # Map CSV fields to MISP Event fields
    event.info = row['Event_Title']
    event.date = row['Event_Date']
    
    # MISP uses numerical IDs for these fields
    # Threat Level: 1 (High), 2 (Medium), 3 (Low), 4 (Undefined)
    threat_map = {'High': 1, 'Medium': 2, 'Low': 3, 'Undefined': 4}
    event.threat_level_id = threat_map.get(row['Threat_Level'], 4)
    
    # Analysis: 0 (Initial), 1 (Ongoing), 2 (Completed)
    analysis_map = {'Initial': 0, 'Ongoing': 1, 'Completed': 2}
    event.analysis = analysis_map.get(row['Analysis'], 0)
    
    # Distribution: 0 (Your Org), 1 (Community), 2 (Connected Communities), 3 (All), 4 (Sharing Group)
    # Use 4 + sharing_group_id once a sharing group is configured in MISP.
    # Defaulting to 0 (Your Organisation Only) so the event is accepted without a sharing group.
    event.distribution = 0
    # event.distribution = 4
    # event.sharing_group_id = <YOUR_SHARING_GROUP_ID>
    
    # Example for setting organization/orgc_id (often handled by the API key)
    # event.orgc_id = 1 # Replace with your MISP Organization ID
    
    print(f"Creating Event: {event.info}")
    return event

def add_attribute_to_event(event, row):
    """Adds a standard MISP Attribute to the event."""
    
    # Skip if Object_Type is specified (handled by add_object_to_event)
    if pd.notna(row['Object_Type']):
        return
        
    # Skip if Value is empty (e.g., File Object rows where Value is blank)
    if pd.isna(row['Value']) and pd.isna(row['Filename']) and pd.isna(row['Bitcoin_Wallet']):
        return
        
    # Handle the Bitcoin Wallet as a specific attribute type 'btc'
    if pd.notna(row['Bitcoin_Wallet']):
        event.add_attribute(
            category=resolve_category('Financial fraud'),  # MISP uses 'Financial fraud' for BTC
            type='btc', 
            value=row['Bitcoin_Wallet'],
            comment=f"Associated with Ransom Note File: {row['Filename']} - {row['Comment']}",
            to_ids=True # Generally set to True for IOCs
        )
        print(f"  -> Added Attribute: btc: {row['Bitcoin_Wallet']}")
        return

    # Handle standard attributes (IOCs 1, 2, 3, 6, 7, 8, 9)
    if pd.notna(row['Value']):
        # Map Confidence to numerical standard, if necessary, or use tags
        # MISP doesn't use confidence on attributes directly, but tags or comments can hold it.
        confidence_comment = f"Confidence: {row['Confidence']}. {row['Comment']}"
        
        event.add_attribute(
            category=resolve_category(row['Category']),
            type=resolve_type(row['Type']),
            value=row['Value'],
            comment=confidence_comment,
            to_ids=True
        )
        print(f"  -> Added Attribute: {row['Type']}: {row['Value']}")
        
def add_object_to_event(event, row):
    """Handles MISP Objects, specifically the 'File Object' (IOC 4)."""
    
    if row['Object_Type'] == 'File':
        file_object = MISPObject('file')
        
        # Add attributes to the File Object
        if pd.notna(row['Filename']):
            file_object.add_attribute('filename', value=row['Filename'], comment=row['Comment'])
        if pd.notna(row['SHA256']):
            file_object.add_attribute('sha256', value=row['SHA256'], to_ids=True)
        if pd.notna(row['MD5']):
            file_object.add_attribute('md5', value=row['MD5'], to_ids=True)
        
        event.add_object(file_object)
        print(f"  -> Added Object: File (filename: {row['Filename']})")
        
    elif row['Filename'] == 'READ_ME_RESTORE.txt' and pd.notna(row['SHA256']):
        # Although not strictly defined as an Object, we can add this file's hashes and name as attributes.
        event.add_attribute(
            category=resolve_category(row['Category']),
            type='filename|sha256', 
            value=f"{row['Filename']}|{row['SHA256']}",
            comment=row['Comment'],
            to_ids=True
        )
        print(f"  -> Added Attribute: Ransom Note (File hash: {row['SHA256']})")


def process_csv(csv_path):
    """Main function to read the CSV and ingest events."""
    try:
        df = pd.read_csv(csv_path)
    except FileNotFoundError:
        print(f"Error: CSV file not found at {csv_path}")
        return

    # Filter for rows that belong to the main event
    event_rows = df[df['Event_Title'] == 'Operation Silent Grid - Multi-Sector Telemetry Anomalies - March 2026']
    if event_rows.empty:
        print("No event data found in CSV.")
        return

    # 1. Create the single event based on the first row's metadata
    event = create_event(event_rows.iloc[0])

    # 2. Add attributes and objects from all rows
    for index, row in event_rows.iterrows():
        # Handle the File Object (IOC 4)
        add_object_to_event(event, row)
        
        # Handle standard Attributes (IOCs 1, 2, 3, 5, 6, 7, 8, 9)
        add_attribute_to_event(event, row)

    # 3. Publish the event to MISP
    try:
        # Saving the event will upload it to MISP
        # To publish immediately, you can use misp.publish(event)
        
        # Save without publishing first:
        response = misp.add_event(event)
        
        if 'errors' in response:
            print("\n--- MISP API Error ---")
            print(json.dumps(response, indent=2))
        else:
            print("\n--- Success ---")
            print(f"Successfully created MISP Event: ID {response['Event']['id']}")
            print(f"Event UUID: {response['Event']['uuid']}")

    except Exception as e:
        print(f"\n--- Critical Error during MISP upload ---")
        print(e)
        
if __name__ == '__main__':
    process_csv(CSV_FILE)