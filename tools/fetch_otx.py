import uuid
import re
import os
from OTXv2 import OTXv2
from dotenv import load_dotenv
from tools.db import cti_collection, assets_collection
from datetime import datetime

# Load environment variables cleanly
load_dotenv()

def get_otx_api_key():
    """Helper to fetch OTX key from DB."""
    try:
        from tools.models import IntegrationsConfig
        config = IntegrationsConfig.query.first()
        if config and config.otx_api_key:
            return config.otx_api_key
    except:
        pass
    return "fc25abbd5405571ce7964d172035472fe76cd93e47cfd33cb84391dc72b2dc87"

def get_ttp_frequency():
    """Returns a dictionary of how many times each TTP has been run."""
    # LOCAL IMPORT: Breaks the circular loop
    from app import app
    from tools.models import db, SimulationResult 
    
    with app.app_context():
        from sqlalchemy import func
        results = db.session.query(
            SimulationResult.ttp_id, 
            func.count(SimulationResult.ttp_id)
        ).group_by(SimulationResult.ttp_id).all()
        return {ttp: count for ttp, count in results}

def smart_fetch_and_store():
    api_key = get_otx_api_key()
    if not api_key:
        print("[!] No OTX API Key found. Skipping sync.")
        return
        
    otx = OTXv2(api_key)
    print("[*] Synchronizing Threat Intelligence (OS Targeted Mode)...")

    try:
        history = get_ttp_frequency()
    except Exception as e:
        print(f"[!] Could not access history, defaulting to empty: {e}")
        history = {}
    
    # Generic Environment Filter: Just look for OS names
    assets = assets_collection.get(include=["metadatas"])
    
    environment_keywords = set()
    if assets and assets['metadatas']:
        for meta in assets['metadatas']:
            os_name = meta.get('os', '').lower()
            if os_name:
                environment_keywords.add(os_name)

    # Fallback if no assets exist but we still want to fetch
    if not environment_keywords:
        environment_keywords = {"windows", "linux", "mac"}
        
    print(f"[*] Environment Filter Active for: {environment_keywords}")

    # Iterate through Pulses (Fast!)
    pulses = otx.getall_iter()
    candidate_pool = []

    for pulse in pulses:
        if len(candidate_pool) >= 15: break # Grab top 15 to give the AI variety

        name = pulse.get('name', 'No Title')
        desc = (pulse.get('description', '') or '').lower()
        
        # Safely extract T-Codes
        ttps = []
        for attack in pulse.get('attack_ids', []):
            if isinstance(attack, dict) and 'id' in attack:
                ttps.append(attack['id'])
            elif isinstance(attack, str):
                ttps.append(attack)
                
        ttps = [m for m in ttps if re.match(r'^T\d{4}', str(m))]

        # ENVIRONMENT GATEKEEPER: Does this pulse mention ANYTHING in our network?
        is_relevant = any(keyword in desc for keyword in environment_keywords)
        if not is_relevant or not ttps:
            continue

        # CALCULATE DIVERSITY SCORE (Lower = Priority)
        pulse_score = sum(history.get(ttp, 0) for ttp in ttps)
        
        candidate_pool.append({
            "score": pulse_score,
            "name": name,
            "desc": desc,
            "ttps": ttps,
            "matched_keywords": [k for k in environment_keywords if k in desc]
        })

    # Sort: Least tested comes first
    candidate_pool.sort(key=lambda x: x['score'])

    # Store the best candidates in ChromaDB
    stored_count = 0
    for item in candidate_pool[:5]: # Store top 5 pulses for the AI to read
        ttp_string = ", ".join(item['ttps'])
        keyword_string = ", ".join(item['matched_keywords'])
        
        # Check if already exists
        pulse_id = str(uuid.uuid4())
        
        cti_collection.add(
            documents=[f"Title: {item['name']}\nDescription: {item['desc']}"],
            metadatas=[{
                "source": "AlienVault OTX", 
                "technique_id": ttp_string,
                "target_keyword": keyword_string,
                "date_added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "title": item['name']
            }],
            ids=[f"otx_fast_{pulse_id}"]
        )
        print(f"[+] STORED (Score {item['score']}): '{item['name'][:40]}...' | TTPs: {ttp_string}")
        stored_count += 1
        
    print(f"[+] Sync Complete. Fast-fetched {stored_count} relevant pulses.")
    
    # Return summary for Orchestrator
    return {
        "stored_count": stored_count,
        "ttps": list(set([ttp for item in candidate_pool[:5] for ttp in item['ttps']]))
    }

if __name__ == "__main__":
    smart_fetch_and_store()