import os
import json
import uuid
import re
import yaml

def assess_safety(command):
    if not command:
        return "safe", "No execution command."
    cmd_lower = command.lower()
    destructive_keywords = [
        "stop-service", "del ", "rm ", "format ", "shutdown", "reboot", 
        "disable-firewall", "reg delete", "net stop", "kill ", "taskkill",
        "clear-eventlog", "wevtutil cl", "sc delete", "remove-item", 
        "stop-process", "mkfs", "vssadmin delete shadows"
    ]
    if any(k in cmd_lower for k in destructive_keywords):
        return "destructive", "Contains potentially disruptive commands (heuristic match)."
    return "safe", "No destructive keywords detected."

def check_and_ingest(app, db, models):
    APTGroup = models['APTGroup']
    APTTTP = models['APTTTP']
    AtomicTest = models['AtomicTest']
    TTPMitigation = models['TTPMitigation']
    from .db import mitre_info, apt_info

    with app.app_context():
        # 1. Ingest APTs to SQLite
        if APTGroup.query.count() == 0:
            json_path = os.path.join('one_time_usage_files', 'apt_groups_mapped.json')
            if os.path.exists(json_path):
                print("[*] Ingesting APTs from JSON...")
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for item in data:
                    name = item.get('name', 'Unknown Group')
                    description = item.get('description', '')
                    aliases = ", ".join(item.get('aliases', []))
                    match = re.search(r'groups/(G\d{4})', description)
                    apt_id = match.group(1) if match else f"custom_{uuid.uuid4().hex[:8]}"
                    while APTGroup.query.get(apt_id):
                        apt_id = f"custom_{uuid.uuid4().hex[:8]}"
                    new_group = APTGroup(id=apt_id, name=name, aliases=aliases, description=description)
                    db.session.add(new_group)
                    seen_ttps = set()
                    for ttp in item.get('used_ttps', []):
                        ttp_id = ttp.get('ttp_id')
                        if ttp_id and ttp_id not in seen_ttps:
                            seen_ttps.add(ttp_id)
                            db.session.add(APTTTP(apt_id=apt_id, ttp_id=ttp_id))
                db.session.commit()
                print("[+] APT Groups ingested.")

        # 2. Ingest Atomics to SQLite and ChromaDB
        if AtomicTest.query.count() == 0:
            print("[*] Ingesting Atomic Red Team library...")
            ATOMICS_DIR = "atomics"
            if os.path.exists(ATOMICS_DIR):
                for ttp_dir in os.listdir(ATOMICS_DIR):
                    full_dir = os.path.join(ATOMICS_DIR, ttp_dir)
                    if not os.path.isdir(full_dir): continue
                    yaml_files = [f for f in os.listdir(full_dir) if f.endswith('.yaml')]
                    if not yaml_files: continue
                    yaml_path = os.path.join(full_dir, yaml_files[0])
                    try:
                        with open(yaml_path, 'r', encoding='utf-8') as f:
                            data = yaml.safe_load(f)
                        ttp_id = data.get('attack_technique')
                        ttp_name = data.get('display_name', 'Unknown TTP')
                        tests_data = data.get('atomic_tests', [])
                        if not ttp_id or not tests_data: continue

                        # Update ChromaDB mitre_info
                        existing_mitre = mitre_info.get(ids=[ttp_id])
                        if not (existing_mitre and existing_mitre['ids']):
                            mitre_info.upsert(
                                ids=[ttp_id],
                                metadatas=[{"id": ttp_id, "name": ttp_name}],
                                documents=[f"### DESCRIPTION ###\n{ttp_name}"]
                            )

                        for test in tests_data:
                            guid = test.get('auto_generated_guid')
                            name = test.get('name', 'Unknown Test')
                            desc = test.get('description', '')
                            platforms = test.get('supported_platforms', [])
                            executor_data = test.get('executor', {})
                            executor = executor_data.get('name', '')
                            command = executor_data.get('command', '')
                            cleanup = executor_data.get('cleanup_command', '')
                            elevation_required = executor_data.get('elevation_required', False)
                            
                            # User context logic
                            user_context = "Standard user"
                            if elevation_required:
                                if any("windows" in p.lower() for p in platforms):
                                    user_context = "Admin user"
                                elif any(p.lower() in ["linux", "macos", "unix", "solaris", "aix"] for p in platforms):
                                    user_context = "root User"
                                else:
                                    # Fallback for elevation but unknown platform
                                    user_context = "Privileged user"

                            input_args = test.get('input_arguments', {})
                            dependencies = test.get('dependencies', [])
                            if input_args:
                                for arg_name, arg_details in input_args.items():
                                    default_val = str(arg_details.get('default', ''))
                                    pattern = re.compile(rf"#\s*{{\s*{re.escape(arg_name)}\s*}}")
                                    if command: command = pattern.sub(default_val, command)
                                    if cleanup: cleanup = pattern.sub(default_val, cleanup)
                            safety_rating, safety_reason = assess_safety(command)
                            new_test = AtomicTest(
                                ttp_id=ttp_id, ttp_name=ttp_name, test_guid=guid, test_name=name,
                                description=desc.strip() if desc else "No description provided.",
                                platforms=",".join(platforms), executor=executor, command=command,
                                cleanup_command=cleanup, dependencies=json.dumps(dependencies),
                                safety_rating=safety_rating, safety_reason=safety_reason,
                                elevation_required=elevation_required,
                                user_context=user_context,
                                required_software=executor.lower() if executor else "", target_apps=""
                            )
                            db.session.add(new_test)
                    except Exception as e:
                        print(f"[!] Error processing {yaml_path}: {e}")
                db.session.commit()
                print("[+] Atomic tests ingested.")

        # 3. Ingest Mitigations
        if TTPMitigation.query.count() == 0:
            json_path = os.path.join('one_time_usage_files', 'ttps_remediation_mapped.json')
            if os.path.exists(json_path):
                print("[*] Ingesting Mitigations...")
                with open(json_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for item in data:
                    ttp_id = item.get('mitre_id')
                    for mit in item.get('mitigations', []):
                        name = mit.get('name', 'Unknown')
                        desc = mit.get('description', '')
                        if ttp_id and name:
                            db.session.add(TTPMitigation(ttp_id=ttp_id, mitigation_name=name, description=desc))
                db.session.commit()
                print("[+] Mitigations ingested.")

        # 4. Seed ChromaDB APTs
        existing_apts = apt_info.get()
        if not existing_apts['ids']:
            print("[*] Seeding APT groups to ChromaDB...")
            APT_SEED_DATA = [
                {"name": "APT29 (Cozy Bear)", "description": "Russian-based espionage.", "ttps": ["T1059.001", "T1071.001", "T1082"]},
                {"name": "Lazarus Group", "description": "North Korean state-sponsored.", "ttps": ["T1059.003", "T1027", "T1071.001"]},
                {"name": "FIN7", "description": "Financially motivated threat group.", "ttps": ["T1059.001", "T1059.005", "T1204.002"]},
                {"name": "APT41", "description": "Chinese state-sponsored espionage.", "ttps": ["T1059.003", "T1053.005", "T1071.001"]},
                {"name": "Wizard Spider", "description": "Russia-based ransomware operations.", "ttps": ["T1486", "T1059.001", "T1482"]}
            ]
            ids, docs, metas = [], [], []
            for apt in APT_SEED_DATA:
                aid = str(uuid.uuid4())
                ids.append(aid)
                docs.append(f"Group: {apt['name']}\nDescription: {apt['description']}\nTTPs: {', '.join(apt['ttps'])}")
                metas.append({"name": apt['name'], "ttps": ",".join(apt['ttps'])})
            apt_info.add(ids=ids, documents=docs, metadatas=metas)
            print("[+] APT groups seeded to ChromaDB.")