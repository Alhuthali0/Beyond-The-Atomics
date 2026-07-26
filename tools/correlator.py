import os
import json
import re
import requests
from tools.db import cti_collection, mitre_info, assets_collection

def extract_text_chunks(documents):
    """Simple chunking to isolate techniques, malware, and tools (Mimics mcp-main/app/rag.py)"""
    # For now, we return as is, but could be expanded for more complex parsing
    return documents

def get_autonomous_decision(excluded_ids=None, target_context="", target_hostname=""):
    """
    Structured RAG pipeline handling STIX/CTI data.
    Uses Multi-Stage Planning (Chain of Thought) to generate attack chains.
    """
    if excluded_ids is None:
        excluded_ids = []

    # Import locally to avoid circular imports
    from tools.models import SoftwareInventory

    # 1. Define the Terrain
    if target_hostname:
        assets = assets_collection.get(ids=[f"target_{target_hostname}"], include=["metadatas", "documents"])
    else:
        assets = assets_collection.get(include=["metadatas", "documents"])
        
    if not assets['metadatas']:
        return {"status": "error", "message": "No active assets found."}

    target_asset = assets['metadatas'][0]
    target_os = target_asset['os'].lower()
    hostname = target_asset.get('hostname', target_hostname)

    # 2. Fetch Software Inventory for structured facts
    inventory = SoftwareInventory.query.filter_by(hostname=hostname).all()
    sw_list = [f"{s.software_name} (v{s.version})" for s in inventory]
    sw_context = "\nInstalled Software:\n- " + "\n- ".join(sw_list) if sw_list else "\nNo software inventory available."

    terrain_facts = target_context if target_context else assets['documents'][0][:2000]
    terrain_facts += sw_context

    # 3. Structured CTI Ingestion (Phase 1, Step 2)
    mitre_results = mitre_info.get(limit=20, include=["documents", "metadatas"])
    structured_mitre = ""
    for i in range(len(mitre_results['documents'])):
        meta = mitre_results['metadatas'][i]
        # Mimic 'name | description' format from MCP
        structured_mitre += f"Name: {meta['name']} | ID: {meta['id']}\nDescription: {mitre_results['documents'][i][:400].strip()}...\n\n"

    threat_desc = "Analyze target vulnerabilities and plan a multi-stage attack chain."

    url = "http://localhost:11434/api/generate"
    forbidden_list = ", ".join(excluded_ids) if excluded_ids else "None"

    # 4. Multi-Stage Planning (Phase 1, Step 3)
    # Using a Chain of Thought style prompt to improve reliability
    prompt = f"""
    You are an autonomous Red Team Planner.
    
    ### TARGET TERRAIN ###
    Hostname: {hostname}
    Operating System: {target_os}
    Assets/Software:
    {terrain_facts}

    ### AVAILABLE MITRE TECHNIQUES ###
    {structured_mitre}

    [CRITICAL] FORBIDDEN TECHNIQUES: {forbidden_list}

    ### TASK ###
    Design a logical Attack Chain. 
    1. First, reason about the target's software and OS.
    2. Identify which available techniques are most likely to succeed.
    3. Output your 'thoughts' on the strategy.
    4. Provide the final attack chain in JSON.

    ### RULES ###
    - If no techniques fit the OS ({target_os}) or software, output status "skip".
    - Avoid forbidden techniques.

    ### OUTPUT FORMAT (STRICT JSON ONLY) ###
    {{
      "thoughts": "Your step-by-step reasoning...",
      "status": "attack_chain" | "skip",
      "chain": [
        {{
          "step": 1,
          "id": "TXXXX",
          "name": "Technique Name",
          "reason": "Why this specifically fits the facts."
        }}
      ]
    }}
    """

    payload = {
        "model": "phi3", 
        "prompt": prompt,
        "format": "json",
        "stream": False
    }

    try:
        response = requests.post(url, json=payload, timeout=120)
        response.raise_for_status()
        res_json = response.json()
        ai_response = res_json.get("response")
        
        try:
            decision = json.loads(ai_response)
            return {"status": "success", "data": decision}
        except:
            match = re.search(r'\{.*\}', ai_response, re.DOTALL)
            if match:
                return {"status": "success", "data": json.loads(match.group(0))}
            return {"status": "error", "message": "AI returned invalid JSON", "raw": ai_response}

    except Exception as e:
        print(f"[-] Error connecting to Ollama: {e}")
        return {"status": "error", "message": str(e)}

def generate_dynamic_payload(ttp_id, ttp_name, target_os, target_facts=""):
    """
    Phase 2: Dynamic Payload Generation Fallback.
    Generates a functional command when a static Atomic test is missing.
    """
    url = "http://localhost:11434/api/generate"
    
    prompt = f"""
    You are an expert Red Team Payload Developer.
    Your task is to generate a functional, single-line command for the following MITRE TTP.

    TTP ID: {ttp_id}
    TTP Name: {ttp_name}
    Target OS: {target_os}
    Target Context: {target_facts}

    ### RULES ###
    1. Output ONLY the command. No explanation, no markdown tags.
    2. The command must be safe for a lab environment but functional.
    3. Use native OS tools (PowerShell/CMD for Windows, Bash for Linux).
    4. If the TTP is too complex for a one-liner, provide a simplified version that demonstrates the technique.

    COMMAND:
    """

    payload = {
        "model": "phi3", 
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(url, json=payload, timeout=60)
        response.raise_for_status()
        res_json = response.json()
        command = res_json.get("response", "").strip()
        # Clean up any potential markdown or quotes
        command = command.replace("```", "").replace("`", "").strip()
        return command
    except Exception as e:
        print(f"[-] Dynamic Payload Generation Failed: {e}")
        return None

if __name__ == "__main__":
    print(get_autonomous_decision())
