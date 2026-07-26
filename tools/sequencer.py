import json
import requests
import re
from tools.db import cti_collection, assets_collection, mitre_info

def package_context(target_hostname):
    """
    Step 1: Context Packaging
    Bundles TTPs, environment details (OS, Ports), and CTI pulse summaries.
    """
    from tools.models import AgentSysInfo, AgentPort
    
    # 1. Get Target Environment Details
    asset = assets_collection.get(ids=[f"target_{target_hostname}"], include=["metadatas", "documents"])
    if not asset or not asset['metadatas']:
        return None
    
    target_meta = asset['metadatas'][0]
    target_os = target_meta.get('os', 'unknown')
    
    # Fetch detailed OS info
    sysinfo = AgentSysInfo.query.filter_by(hostname=target_hostname).first()
    os_details = sysinfo.os_version if sysinfo else target_os

    # Fetch Open Ports
    ports = AgentPort.query.filter_by(hostname=target_hostname).all()
    open_ports = [f"{p.port}/{p.protocol} ({p.service_name})" for p in ports]
    
    # 2. Get Top 5 Pulses (CTI Context)
    pulses = cti_collection.get(limit=5, include=["documents", "metadatas"])
    pulse_summaries = []
    all_ttps = []
    
    for i in range(len(pulses['documents'])):
        doc = pulses['documents'][i]
        meta = pulses['metadatas'][i]
        pulse_summaries.append({
            "title": meta.get('title', 'Unknown Pulse'),
            "description": doc[:500] + "...",
            "ttps": meta.get('technique_id', '').split(',')
        })
        all_ttps.extend(meta.get('technique_id', '').split(','))
    
    # Unique TTPs only
    unique_ttps = list(set([t.strip() for t in all_ttps if t.strip()]))
    
    return {
        "hostname": target_hostname,
        "os_details": os_details,
        "open_ports": open_ports,
        "pulse_summaries": pulse_summaries,
        "unique_ttps": unique_ttps
    }

def get_agentic_sequence(context_payload):
    """
    Step 2 & 3: Agentic Sorting Engine and Structured Output Parsing
    """
    if not context_payload or not context_payload['unique_ttps']:
        return None

    url = "http://localhost:11434/api/generate" # Default Ollama URL
    
    # Build the sequencing prompt
    prompt = f"""
    You are an expert Cyber Attack Coordinator. 
    Your goal is to sequence a set of MITRE ATT&CK techniques into a logical, realistic attack path.

    ### TARGET CONTEXT ###
    Hostname: {context_payload['hostname']}
    Operating System: {context_payload['os_details']}
    Open Ports: {', '.join(context_payload['open_ports']) if context_payload['open_ports'] else 'None detected'}

    ### CTI SOURCE SUMMARIES ###
    {json.dumps(context_payload['pulse_summaries'], indent=2)}

    ### IDENTIFIED TECHNIQUES (TTPs) ###
    {", ".join(context_payload['unique_ttps'])}

    ### TASK ###
    1. Analyze the TTPs and the CTI context.
    2. Determine the most realistic execution order based on the Cyber Kill Chain phases:
       (Initial Access -> Execution -> Persistence -> Privilege Escalation -> Defense Evasion -> Credential Access -> Discovery -> Lateral Movement -> Collection -> Command and Control -> Exfiltration -> Impact).
    3. [CRITICAL] You MUST include EVERY TTP provided in the list above. Do NOT filter, remove, or skip any technique.
    4. For each TTP in the sequence, provide a brief (one sentence) justification.

    ### OUTPUT FORMAT (STRICT JSON ONLY) ###
    {{
      "reasoning": "Global explanation for this attack path...",
      "sequence": [
        {{
          "id": "TXXXX",
          "justification": "Why this step comes now in the sequence."
        }}
      ]
    }}
    """

    payload = {
        "model": "phi3", 
        "prompt": prompt,
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }

    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        ai_response = response.json().get("response", "")
        
        # Step 3: Parsing
        try:
            decision = json.loads(ai_response)
            return decision
        except:
            # Fallback regex if JSON is wrapped in text
            match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if match:
                return json.loads(match.group(0))
            return None
            
    except Exception as e:
        print(f"[-] Sequencer Error: {e}")
        return None

def apply_sequence_to_work_items(work_items, sequence_data):
    """
    Reorders the execution queue based on the AI's sequence.
    """
    if not sequence_data or "sequence" not in sequence_data:
        return work_items
    
    ordered_ids = [item['id'] for item in sequence_data['sequence']]
    justifications = {item['id']: item['justification'] for item in sequence_data['sequence']}
    
    new_work_items = []
    
    # First, add items that are in the AI's sequence, in order
    for ttp_id in ordered_ids:
        for item in work_items:
            if item[2] == ttp_id:
                # Append the justification to the work item metadata if possible, 
                # or we'll handle it during report generation
                new_work_items.append(item)
                # Note: We don't break here because the same TTP might be for different hosts, 
                # but usually work_items are (host, os, ttp)
    
    # Then add any remaining items that weren't in the sequence (just in case)
    already_added = [item[2] for item in new_work_items]
    for item in work_items:
        if item[2] not in already_added:
            new_work_items.append(item)
            
    return new_work_items, justifications
