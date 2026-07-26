import os
import yaml
from app import app, db, AtomicTest
from db import mitre_info
import re
import json

ATOMICS_DIR = "atomics"

def assess_safety(command):
    """Offline heuristic to determine if an atomic test is safe to run."""
    if not command:
        return "safe", "No execution command."
    
    cmd_lower = command.lower()
    
    # Strict list of destructive keywords
    destructive_keywords = [
        "stop-service", "del ", "rm ", "format ", "shutdown", "reboot", 
        "disable-firewall", "reg delete", "net stop", "kill ", "taskkill",
        "clear-eventlog", "wevtutil cl", "sc delete", "remove-item", 
        "stop-process", "mkfs", "vssadmin delete shadows"
    ]
    
    if any(k in cmd_lower for k in destructive_keywords):
        return "destructive", "Contains potentially disruptive commands (heuristic match)."
    
    return "safe", "No destructive keywords detected."

def ingest_atomics():
    print("[*] Starting offline ingestion of Atomic Red Team library...")
    
    with app.app_context():
        print("[*] Wiping old AtomicTest database to start fresh...")
        AtomicTest.query.delete()
        db.session.commit()
        
        test_count = 0
        ttp_count = 0
        
        for ttp_dir in os.listdir(ATOMICS_DIR):
            full_dir = os.path.join(ATOMICS_DIR, ttp_dir)
            if not os.path.isdir(full_dir): 
                continue
            
            # Find the YAML file
            yaml_files = [f for f in os.listdir(full_dir) if f.endswith('.yaml')]
            if not yaml_files:
                continue
                
            yaml_path = os.path.join(full_dir, yaml_files[0])
            
            try:
                with open(yaml_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                
                ttp_id = data.get('attack_technique')
                ttp_name = data.get('display_name', 'Unknown TTP')
                tests_data = data.get('atomic_tests', [])
                
                if not ttp_id or not tests_data:
                    continue

                # 1. Update ChromaDB so the TTPs page can show the description
                # If there's no description in the YAML root, we use the name to prevent Chroma crashes
                existing_mitre = mitre_info.get(ids=[ttp_id])
                if existing_mitre and existing_mitre['ids']:
                    mitre_info.update(
                        ids=[ttp_id],
                        metadatas=[{"id": ttp_id, "name": ttp_name}]
                    )
                else:
                    mitre_info.upsert(
                        ids=[ttp_id],
                        metadatas=[{"id": ttp_id, "name": ttp_name}],
                        documents=[f"### DESCRIPTION ###\n{ttp_name}"]
                    )

                # 2. Process and save each test
                for test in tests_data:
                    guid = test.get('auto_generated_guid')
                    name = test.get('name', 'Unknown Test')
                    desc = test.get('description', '')
                    platforms = test.get('supported_platforms', [])
                    
                    executor_data = test.get('executor', {})
                    executor = executor_data.get('name', '')
                    command = executor_data.get('command', '')
                    cleanup = executor_data.get('cleanup_command', '')
                    
                    # Resolve input variables (e.g. #{image_file})
                    input_args = test.get('input_arguments', {})
                    dependencies = test.get('dependencies', [])
                    if input_args:
                        for arg_name, arg_details in input_args.items():
                            default_val = str(arg_details.get('default', ''))
                            pattern = re.compile(rf"#\s*{{\s*{re.escape(arg_name)}\s*}}")
                            if command: command = pattern.sub(default_val, command)
                            if cleanup: cleanup = pattern.sub(default_val, cleanup)
                            for dep in dependencies:
                                if 'prereq_command' in dep and dep['prereq_command']:
                                    dep['prereq_command'] = pattern.sub(default_val, dep['prereq_command'])
                                if 'get_prereq_command' in dep and dep['get_prereq_command']:
                                    dep['get_prereq_command'] = pattern.sub(default_val, dep['get_prereq_command'])

                    # Assess Safety
                    safety_rating, safety_reason = assess_safety(command)

                    # Extract software requirements
                    req_sw = set()
                    if executor: 
                        req_sw.add(executor.lower())
                    
                    # Create the database record
                    new_test = AtomicTest(
                        ttp_id=ttp_id,
                        ttp_name=ttp_name,
                        test_guid=guid,
                        test_name=name,
                        description=desc.strip() if desc else "No description provided.",
                        platforms=",".join(platforms),
                        executor=executor,
                        command=command,
                        cleanup_command=cleanup,
                        dependencies=json.dumps(dependencies),
                        safety_rating=safety_rating,
                        safety_reason=safety_reason,
                        required_software=",".join(list(req_sw)),
                        target_apps="" # Can be expanded later if needed
                    )
                    db.session.add(new_test)
                    test_count += 1
                
                ttp_count += 1
                
            except Exception as e:
                print(f"[!] Error processing {yaml_path}: {e}")
        
        db.session.commit()
        print(f"[+] Success! Ingested {test_count} tests across {ttp_count} TTPs.")

if __name__ == "__main__":
    ingest_atomics()