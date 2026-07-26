import json
import time
import random
from datetime import datetime
from tools.fetch_otx import smart_fetch_and_store
from tools.sequencer import package_context, get_agentic_sequence, apply_sequence_to_work_items
from tools.atomic_fetcher import fetch_atomic_test
from tools.executor import run_remote_emulation
from tools.db import cti_collection, assets_collection, mitre_info, execution_history
from tools.shared_state import stop_full_cycle
import tools.shared_state

class AIOrchestrator:
    def __init__(self, ollama_url="http://localhost:11434", model="phi3"):
        self.ollama_url = ollama_url
        self.model = model

    def orchestrate_full_cycle(self):
        """
        Refactored Full Cycle:
        1. Sync CTI.
        2. Discover targets.
        3. Execute static TTP list (No AI sequencing).
        4. Trigger AI for post-execution DFIR verdict and scoring.
        """
        tools.shared_state.stop_full_cycle = False
        
        yield {"event": "system", "message": "Orchestrator: Initiating Full Cycle. Step 1: Fetching Threat Intelligence..."}
        try:
            summary = smart_fetch_and_store()
            ttp_count = len(summary.get('ttps', []))
            pulse_count = summary.get('stored_count', 0)
            yield {
                "event": "system", 
                "message": f"Threat Intelligence Fetched: Identified {pulse_count} relevant pulses and {ttp_count} unique TTPs for your environment."
            }
            yield {"event": "system", "message": "CTI Sync Complete. Discovering active assets..."}
        except Exception as e:
            yield {"event": "system", "message": f"CTI Sync failed: {str(e)}. Proceeding with cached data..."}

        from app import get_active_targets, pretty_os_label, build_target_context, get_siem_config_dict, find_cti_context_for_ttp, get_ttp_description, get_target_ttps
        from tools.models import SimulationResult, db
        from tools.correlator import generate_dynamic_payload

        targets = get_active_targets()
        if not targets:
            yield {"event": "system", "message": "No active assets found."}
            return

        dispatch_list = [{"hostname": t["hostname"], "os": pretty_os_label(t["os"])} for t in targets]
        work_items = []
        
        # User requested dynamic CTI-based TTPs for Quick Scan
        for tinfo in targets:
            hostname = tinfo["hostname"]
            target_os = tinfo["os"]
            
            # Fetch TTPs specifically mapped to this target based on CTI
            candidate_ttps, _, _ = get_target_ttps(hostname)
            
            # Take up to 5 highest priority CTI TTPs for the quick scan
            for ttp_id in candidate_ttps[:5]:
                work_items.append((hostname, target_os, ttp_id, 0)) # Default to test index 0

        yield {"event": "dispatch", "targets": dispatch_list, "total": len(work_items)}

        results_cache = []

        for hostname, target_os, ttp_id, test_index in work_items:
            if tools.shared_state.stop_full_cycle:
                yield {"event": "system", "message": "🛑 Stop signal received."}
                break

            mitre_res = mitre_info.get(where={"id": ttp_id}, include=["metadatas"])
            ttp_name = mitre_res["metadatas"][0]["name"] if mitre_res and mitre_res.get("metadatas") else ttp_id

            # CTI-style message
            yield {
                "event": "system", 
                "message": f"[CTI] High-confidence intelligence suggests {ttp_id} ({ttp_name}) is being leveraged in active campaigns targeting {target_os} systems."
            }
            
            yield {"event": "attack", "target": hostname, "ttp_id": ttp_id, "ttp_name": ttp_name}

            raw_data = fetch_atomic_test(ttp_id, target_os, test_index=test_index)
            cti_context = find_cti_context_for_ttp(ttp_id)

            payload_cmd = ""
            cleanup_cmd = None
            dependencies = []

            if not raw_data or "test" not in raw_data:
                payload_cmd = generate_dynamic_payload(ttp_id, ttp_name, target_os, cti_context)
            else:
                payload_cmd = raw_data["test"]["executor"].get("command", "")
                cleanup_cmd = raw_data["test"]["executor"].get("cleanup_command", None)
                dependencies = raw_data.get("dependencies", [])

            if not payload_cmd:
                yield {"event": "result", "target": hostname, "ttp_id": ttp_id, "status": "Skipped", "output": "No payload available."}
                results_cache.append("skipped")
                continue

            # Execute
            result = run_remote_emulation(
                command=payload_cmd,
                cleanup_command=cleanup_cmd,
                ttp_id=ttp_id,
                ttp_name=ttp_name,
                target_hostname=hostname,
                target_os=target_os,
                dependencies=dependencies,
                ttp_desc=get_ttp_description(ttp_id),
                siem_config=get_siem_config_dict(),
                target_context=build_target_context(hostname),
                test_name=ttp_name
            )

            # --- AI Post-Analysis ---
            from tools.agentic_engine import analyze_test_result
            asset = assets_collection.get(ids=[f"target_{hostname}"], include=["metadatas"])
            classification = asset['metadatas'][0].get('asset_classification', 'Internal Server') if asset and asset['metadatas'] else 'Internal Server'

            ai_analysis = analyze_test_result(
                ttp_id=ttp_id,
                command=payload_cmd,
                target_os=target_os,
                exit_code=result.get('exit_code', 0),
                stdout=result.get('output', ''),
                stderr=result.get('stderr', ''),
                wazuh_severity=result.get('wazuh_severity', 'N/A'),
                wazuh_rule_desc=result.get('wazuh_rule_desc', 'N/A'),
                asset_classification=classification,
                test_name=ttp_name,
                ollama_url=self.ollama_url,
                target_hostname=hostname
            )

            # Populate RAG Database
            rag_text = f"TTP {ttp_name} ({ttp_id}) ran on {hostname} via command {payload_cmd}. The exit code was {result.get('exit_code')}. Status: {result.get('sec_status')}. Output: {result.get('output')}."
            try:
                execution_history.add(
                    documents=[rag_text],
                    ids=[f"sim_{ttp_id}_{time.time()}"],
                    metadatas=[{"hostname": hostname, "ttp": ttp_id}]
                )
            except Exception as e:
                print(f"Failed to populate RAG DB: {e}")

            # Persist Result
            new_rec = SimulationResult(
                ttp_id=ttp_id,
                ttp_name=ttp_name,
                target_hostname=hostname,
                status=result.get('sec_status', 'Executed'),
                output=result.get('output'),
                stderr=result.get('stderr'),
                exit_code=result.get('exit_code'),
                start_time=result.get('start_time'),
                end_time=result.get('end_time'),
                status_run=result.get('status_run'),
                status_detected=result.get('status_detected'),
                execution_type='Quick Scan',
                reasoning="Automated quick scan for basic control validation.",
                ai_reasoning=json.dumps(ai_analysis),
                calculated_score=ai_analysis.get('calculated_score'),
                calculation_reasoning=ai_analysis.get('calculation_reasoning'),
                execution_status=ai_analysis.get('execution_status'),
                dfir_verdict=ai_analysis.get('dfir_verdict'),
                test_name=ttp_name,
                wazuh_severity=result.get('wazuh_severity'),
                wazuh_rule_desc=result.get('wazuh_rule_desc'),
                cti_context=cti_context,
                wazuh_agent_id=result.get('siem_metadata', {}).get('agent_id'),
                executed_command=payload_cmd,
                spawned_processes=json.dumps(result.get('siem_metadata', {}).get('spawned_processes', [])),
                created_files=json.dumps(result.get('siem_metadata', {}).get('created_files', [])),
                parent_process=json.dumps(result.get('siem_metadata', {}).get('parent_processes', []))
            )
            db.session.add(new_rec)
            db.session.commit()

            status_low = result.get('sec_status', '').lower()
            results_cache.append(status_low)

            yield {
                "event": "result", 
                "target": hostname, 
                "ttp_id": ttp_id, 
                "status": result.get('sec_status'), 
                "output": result.get('output'),
                "ai_analysis": ai_analysis
            }

        # Emit Summary
        summary = {
            "total": len(results_cache),
            "executed": len(results_cache) - results_cache.count("skipped"),
            "vulnerable": sum(1 for s in results_cache if "gap" in s or "missed" in s),
            "protected": sum(1 for s in results_cache if "alerted" in s or "prevented" in s),
            "skipped": results_cache.count("skipped")
        }
        yield {"event": "summary", **summary}
        yield {"event": "system", "message": "Full Cycle Completed."}

    def orchestrate_group_execution(self, hostname, ttp_ids):
        """
        Refactored Group Execution: Execute in order, AI at the end.
        """
        from app import build_target_context, get_siem_config_dict, find_cti_context_for_ttp, get_ttp_description
        from tools.models import SimulationResult, db
        from tools.correlator import generate_dynamic_payload

        yield {"event": "system", "message": f"Executing Group Scan for {hostname}..."}

        target_os = "windows"
        asset = assets_collection.get(ids=[f"target_{hostname}"], include=["metadatas"])
        classification = "Internal Server"
        if asset and asset['metadatas']:
            target_os = asset['metadatas'][0].get('os', 'windows').lower()
            classification = asset['metadatas'][0].get('asset_classification', 'Internal Server')

        for ttp_id in ttp_ids:
            mitre_res = mitre_info.get(where={"id": ttp_id}, include=["metadatas"])
            ttp_name = mitre_res["metadatas"][0]["name"] if mitre_res and mitre_res.get("metadatas") else ttp_id
            
            raw_data = fetch_atomic_test(ttp_id, target_os)
            payload_cmd = ""
            cleanup_cmd = None
            if raw_data and "test" in raw_data:
                payload_cmd = raw_data["test"]["executor"].get("command", "")
                cleanup_cmd = raw_data["test"]["executor"].get("cleanup_command", None)
            
            if not payload_cmd:
                payload_cmd = generate_dynamic_payload(ttp_id, ttp_name, target_os, "")
            
            yield {"event": "attack", "target": hostname, "ttp_id": ttp_id, "ttp_name": ttp_name, "command": payload_cmd}
            
            if not payload_cmd: continue

            result = run_remote_emulation(
                command=payload_cmd,
                cleanup_command=cleanup_cmd,
                ttp_id=ttp_id,
                ttp_name=ttp_name,
                target_hostname=hostname,
                target_os=target_os,
                siem_config=get_siem_config_dict(),
                target_context=build_target_context(hostname)
            )

            from tools.agentic_engine import analyze_test_result
            ai_analysis = analyze_test_result(
                ttp_id, 
                payload_cmd, 
                target_os, 
                result.get('exit_code',0), 
                result.get('output',''), 
                result.get('stderr',''), 
                result.get('wazuh_severity',''), 
                result.get('wazuh_rule_desc',''), 
                asset_classification=classification,
                test_name=ttp_name,
                target_hostname=hostname
            )

            new_rec = SimulationResult(
                ttp_id=ttp_id, ttp_name=ttp_name, target_hostname=hostname,
                status=result.get('sec_status'), output=result.get('output'),
                stderr=result.get('stderr'),
                exit_code=result.get('exit_code'),
                start_time=result.get('start_time'),
                end_time=result.get('end_time'),
                status_run=result.get('status_run'),
                status_detected=result.get('status_detected'),
                execution_type='Group Execution',
                reasoning="Static group execution with AI post-analysis.",
                ai_reasoning=json.dumps(ai_analysis),
                calculated_score=ai_analysis.get('calculated_score'),
                calculation_reasoning=ai_analysis.get('calculation_reasoning'),
                execution_status=ai_analysis.get('execution_status'),
                dfir_verdict=ai_analysis.get('dfir_verdict'),
                wazuh_severity=result.get('wazuh_severity'),
                wazuh_rule_desc=result.get('wazuh_rule_desc'),
                wazuh_agent_id=result.get('siem_metadata', {}).get('agent_id'),
                executed_command=payload_cmd,
                spawned_processes=json.dumps(result.get('siem_metadata', {}).get('spawned_processes', [])),
                created_files=json.dumps(result.get('siem_metadata', {}).get('created_files', [])),
                parent_process=json.dumps(result.get('siem_metadata', {}).get('parent_processes', []))
            )
            db.session.add(new_rec)
            db.session.commit()
            yield {"event": "result", "target": hostname, "ttp_id": ttp_id, "status": result.get('sec_status'), "ai_analysis": ai_analysis}

    def orchestrate_manual_execution(self, hostname, ttp_id, test_guid=None):
        """
        Direct execution followed by AI analysis.
        Uses local database for precise test selection if GUID is provided.
        """
        from app import build_target_context, get_siem_config_dict, get_ttp_description, find_cti_context_for_ttp
        from tools.models import SimulationResult, db, AtomicTest
        from tools.correlator import generate_dynamic_payload
        from tools.agentic_engine import analyze_test_result

        asset = assets_collection.get(ids=[f"target_{hostname}"], include=["metadatas"])
        target_os = "windows"
        classification = "Internal Server"
        if asset and asset['metadatas']:
            target_os = asset['metadatas'][0].get('os', 'windows').lower()
            classification = asset['metadatas'][0].get('asset_classification', 'Internal Server')

        payload_cmd = ""
        cleanup_cmd = None
        ttp_name = ttp_id
        dependencies = []

        # 1. Try to fetch from local database if GUID is provided
        if test_guid:
            test_rec = AtomicTest.query.filter_by(test_guid=test_guid).first()
            if test_rec:
                # Check compatibility
                platforms = [p.strip().lower() for p in test_rec.platforms.split(',')] if test_rec.platforms else []
                if target_os in platforms or 'all' in platforms:
                    payload_cmd = test_rec.command
                    cleanup_cmd = test_rec.cleanup_command
                    ttp_name = test_rec.test_name
                    dependencies = json.loads(test_rec.dependencies) if test_rec.dependencies else []
                else:
                    print(f"[*] GUID {test_guid} is not compatible with {target_os}. Falling back to first compatible test for {ttp_id}.")
                    test_guid = None # Trigger fallback

        # 2. Fallback: Fetch first compatible test if no GUID or GUID mismatch
        if not payload_cmd:
            # First try local database for any compatible test for this TTP
            test_rec = AtomicTest.query.filter(
                AtomicTest.ttp_id == ttp_id,
                (AtomicTest.platforms.like(f"%{target_os}%")) | (AtomicTest.platforms.like("%all%"))
            ).first()
            
            if test_rec:
                payload_cmd = test_rec.command
                cleanup_cmd = test_rec.cleanup_command
                ttp_name = test_rec.test_name
                dependencies = json.loads(test_rec.dependencies) if test_rec.dependencies else []
            else:
                # Fallback to GitHub fetcher
                raw_data = fetch_atomic_test(ttp_id, target_os)
                if raw_data and "test" in raw_data:
                    payload_cmd = raw_data["test"]["executor"].get("command", "")
                    cleanup_cmd = raw_data["test"]["executor"].get("cleanup_command", None)
                    ttp_name = raw_data["test"].get("name", ttp_id)
                    dependencies = raw_data.get("dependencies", [])
                else:
                    payload_cmd = generate_dynamic_payload(ttp_id, ttp_id, target_os, "")
        
        if not payload_cmd:
            return {"sec_status": "Error", "output": "No payload."}

        result = run_remote_emulation(
            command=payload_cmd,
            cleanup_command=cleanup_cmd,
            ttp_id=ttp_id,
            ttp_name=ttp_name,
            target_hostname=hostname,
            target_os=target_os,
            dependencies=dependencies,
            siem_config=get_siem_config_dict(),
            target_context=build_target_context(hostname),
            test_name=ttp_name
        )

        ai_analysis = analyze_test_result(
            ttp_id, 
            payload_cmd, 
            target_os, 
            result.get('exit_code',0), 
            result.get('output',''), 
            result.get('stderr',''), 
            result.get('wazuh_severity',''), 
            result.get('wazuh_rule_desc',''), 
            asset_classification=classification,
            test_name=ttp_name,
            target_hostname=hostname
        )

        new_rec = SimulationResult(
            ttp_id=ttp_id, ttp_name=ttp_name, target_hostname=hostname,
            status=result.get('sec_status'), output=result.get('output'),
            stderr=result.get('stderr'),
            exit_code=result.get('exit_code'),
            start_time=result.get('start_time'),
            end_time=result.get('end_time'),
            status_run=result.get('status_run'),
            status_detected=result.get('status_detected'),
            execution_type='Manual Execution',
            reasoning="Direct manual execution verified by AI.",
            ai_reasoning=json.dumps(ai_analysis),
            calculated_score=ai_analysis.get('calculated_score'),
            calculation_reasoning=ai_analysis.get('calculation_reasoning'),
            execution_status=ai_analysis.get('execution_status'),
            dfir_verdict=ai_analysis.get('dfir_verdict'),
            wazuh_severity=result.get('wazuh_severity'),
            wazuh_rule_desc=result.get('wazuh_rule_desc'),
            cti_context="Manual Trigger",
            wazuh_agent_id=result.get('siem_metadata', {}).get('agent_id'),
            executed_command=payload_cmd,
            spawned_processes=json.dumps(result.get('siem_metadata', {}).get('spawned_processes', [])),
            created_files=json.dumps(result.get('siem_metadata', {}).get('created_files', [])),
            parent_process=json.dumps(result.get('siem_metadata', {}).get('parent_processes', []))
        )
        db.session.add(new_rec)
        db.session.commit()
        
        return result
