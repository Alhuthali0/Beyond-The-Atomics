from smolagents import tool
from tools.fetch_otx import smart_fetch_and_store
from tools.executor import run_remote_emulation
from tools.atomic_fetcher import fetch_atomic_test
from tools.db import cti_collection, assets_collection
from tools.correlator import get_autonomous_decision

@tool
def sync_threat_intel() -> str:
    """
    Fetches the latest threat intelligence from AlienVault OTX and stores it in the vector database.
    Use this tool FIRST when starting a new threat emulation cycle to ensure you have the latest data.
    """
    try:
        smart_fetch_and_store()
        return "Successfully fetched and stored the latest threat intelligence."
    except Exception as e:
        return f"Failed to sync intel: {str(e)}"

@tool
def get_target_os(hostname: str = None) -> str:
    """
    Retrieves the operating system of the target asset.
    
    Args:
        hostname: The exact hostname of the target machine. If None, defaults to the first discovered asset.
    """
    assets = assets_collection.get(include=["metadatas"])
    if not assets['metadatas']:
        return "unknown"
        
    if hostname:
        for meta in assets['metadatas']:
            if meta.get('hostname') == hostname:
                return meta.get('os').lower()
                
    return assets['metadatas'][0]['os'].lower()

@tool
def get_atomic_payload(ttp_id: str, target_os: str) -> dict:
    """
    Fetches the execution command and cleanup command for a specific MITRE ATT&CK technique.
    
    Args:
        ttp_id: The MITRE Technique ID (e.g., 'T1053.005').
        target_os: The operating system of the target (e.g., 'windows').
    """
    data = fetch_atomic_test(ttp_id, target_os)
    if data and 'test' in data:
       
        return {
            "command": data['test']['executor'].get('command', ''),
            "cleanup_command": data['test']['executor'].get('cleanup_command', None),
            "input_arguments": data['test'].get('input_arguments', {})
        }
        
    return {"command": f"Error: No payload found for {ttp_id} on {target_os}.", "cleanup_command": None}

@tool
def execute_payload(command: str, cleanup_command: str = None, ttp_id: str = None) -> str:
    """
    Executes a command-line payload on the local machine for Breach and Attack Simulation.
    
    Args:
        command: The exact shell command or PowerShell script to execute.
        cleanup_command: The command to revert changes and clean up the system.
        ttp_id: Optional MITRE Technique ID (e.g., 'T1053.005').
    """
    assets = assets_collection.get(include=["metadatas"])
    if not assets or not assets['metadatas']:
         return "Error: No active agents found."

    target_host = assets['metadatas'][0].get('hostname', 'Unknown')
    target_os = assets['metadatas'][0].get('os', 'windows').lower()
    
    # In a more advanced scenario, we'd build the target_context here too.
    # For simplicity in this tool, we'll let run_remote_emulation handle the basics.
        
    result = run_remote_emulation(
        command=command, 
        target_hostname=target_host, 
        cleanup_command=cleanup_command, 
        ttp_id=ttp_id, 
        target_os=target_os
    )

    return f"Execution Status: {result.get('sec_status', 'Unknown')}\nOutput: {result['output']}"

@tool
def decide_best_technique() -> dict:
    """
    Analyzes the latest threat intelligence against the local asset inventory.
    Use this tool to determine WHICH MITRE technique you should attack with.
    Returns a dictionary with 'status', 'id' (the TTP ID), 'name', and 'reasoning'.
    """
    return get_autonomous_decision()
