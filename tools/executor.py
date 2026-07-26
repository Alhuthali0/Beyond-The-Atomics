import base64
import re
import time
import requests
from requests.auth import HTTPBasicAuth
import urllib3
from tools.shared_state import pending_tasks, agent_results
import json
import tools.siem_check # Import the new SIEM checker
from tools.agentic_engine import analyze_test_result

# Suppress insecure request warnings for self-signed certificates (Wazuh default)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from datetime import datetime, timezone, timedelta

# =========================================================================
# L3 VERIFICATION: WAZUH SIEM API INTEGRATION (DELEGATED TO siem_check.py)
# =========================================================================

def verify_with_siem(ttp_id, target_hostname, start_time, end_time, agent_id, siem_config, command=None):
    """
    Queries the Wazuh SIEM using the standalone siem_check agent.
    Returns: bool (True if alerted, False otherwise)
    """
    if not siem_config or not siem_config.get('enabled'):
        return False

    print(f"[*] Waiting 20s for SIEM ingestion...")
    time.sleep(20)
    
    wazuh_ip = siem_config.get('ip')
    user = siem_config.get('user')
    password = siem_config.get('password')

    # Use the separate agent to perform the check
    result = tools.siem_check.check_alerts(
        ttp_id=ttp_id,
        agent_id=agent_id,
        start_time=start_time,
        end_time=end_time,
        wazuh_ip=wazuh_ip,
        user=user,
        password=password,
        command=command
    )
    
    if result.get("status") == "success":
        if result.get("alerted"):
            print(f"[+] SIEM Match! Found {result.get('count')} alerts via siem_check agent.")
            return True
    else:
        print(f"[!] siem_check Error: {result.get('message')}")
        
    return False

def resolve_variables_and_paths(text, input_arguments, target_os, target_context=None):
    """
    Phase 3: Variable Interpolation Engine.
    Stage 1: Variable & Path Resolution
    Replaces PathToAtomicsFolder with a remote staging path and #{variable_name} 
    with their resolved values from YAML arguments or dynamic target context.
    """
    if not text:
        return ""
        
    # 1. Replace PathToAtomicsFolder
    staging_path = "$env:TEMP\\atomics" if target_os.lower() == "windows" else "/tmp/atomics"
    # Case-insensitive replacement for PathToAtomicsFolder
    text = re.sub(r'(?i)PathToAtomicsFolder', staging_path, text)
    
    # 2. Collect all potential values
    context = target_context or {}
    
    # Match #{var_name}
    matches = re.findall(r'#\{([a-zA-Z0-9_]+)\}', text)
    for var in matches:
        val = None
        
        # A. Check provided context (SoftwareInventory, SysInfo, etc.)
        if var in context:
            val = str(context[var])
        
        # B. Check input_arguments (Static Defaults from YAML)
        if not val and input_arguments and var in input_arguments:
            val = input_arguments[var].get("default", "")

        # C. Smart Defaults based on OS for common Atomic variables
        if not val:
            smart_defaults = {
                "filepath": "C:\\Windows\\Temp\\atomic_test.txt" if target_os == "windows" else "/tmp/atomic_test.txt",
                "filename": "atomic_test.txt",
                "user": "Administrator" if target_os == "windows" else "root",
                "temp_dir": "C:\\Windows\\Temp" if target_os == "windows" else "/tmp",
                "ip_address": "127.0.0.1"
            }
            val = smart_defaults.get(var)

        # D. Perform Replacement
        if val is not None:
            # Pattern to match #{var} with optional whitespace
            pattern = re.compile(rf"#\s*{{\s*{re.escape(var)}\s*}}")
            text = pattern.sub(str(val), text)
            
    return text

def build_staged_payload(command, input_arguments, target_os, target_context=None, elevation_required=False):
    """
    Stage 2: Staged Script Builder
    Creates a wrapper script for a single command.
    
    Stage 3: Payload Delivery Preparation
    Base64 encodes the script for safe transport to the agent.
    """
    if not command:
        return ""
        
    is_windows = (target_os or "windows").lower() == "windows"
    
    # Resolve variables in command
    resolved_command = resolve_variables_and_paths(command, input_arguments, target_os, target_context)
    
    # Linux-specific elevation logic (sudo -n for non-interactive)
    if not is_windows and elevation_required:
        if "sudo " in resolved_command and "sudo -n " not in resolved_command:
            resolved_command = resolved_command.replace("sudo ", "sudo -n ")
        elif "sudo " not in resolved_command:
            resolved_command = f"sudo -n {resolved_command}"

    # Base64 Encode payload
    encoded_bytes = base64.b64encode(resolved_command.encode('utf-8'))
    encoded_script = encoded_bytes.decode('utf-8')
    
    # Prepare final payload for safe remote execution
    # Echo-Extraction Method: Capture true exit code BEFORE delimiter resets it
    if is_windows:
        final_payload = (
            f"$c = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded_script}')); "
            f"Invoke-Expression $c *>&1; "
            f"$CODE = $LASTEXITCODE; "
            f"if ($? -eq $false -and $CODE -eq 0) {{ $CODE = 1 }}; "
            f"Write-Output '---TRUE_EXIT_CODE---'; "
            f"Write-Output $CODE"
        )
    else:
        final_payload = (
            f"cd / && "
            f"echo {encoded_script} | base64 -d | bash 2>&1; "
            f"CODE=$?; "
            f"echo '---TRUE_EXIT_CODE---'; "
            f"echo $CODE"
        )

    return final_payload

def run_remote_command(command, target_hostname, timeout_secs=60):
    """Queues a command and returns (exit_code, stdout, stderr)."""
    print(f"[*] Dispatching task to {target_hostname}: {command}")
    pending_tasks[target_hostname] = command
    
    timeout = timeout_secs
    while timeout > 0:
        if target_hostname in agent_results:
            result = agent_results.pop(target_hostname)
            
            raw_stdout = ""
            original_stderr = ""
            
            # Extract raw text regardless of format
            if isinstance(result, dict):
                raw_stdout = result.get("stdout", "")
                original_stderr = result.get("stderr", "")
            else:
                raw_stdout = str(result)
            
            # --- ECHO-EXTRACTION PARSING ---
            delimiter = "---TRUE_EXIT_CODE---"
            if delimiter in raw_stdout:
                parts = raw_stdout.split(delimiter)
                clean_stdout = parts[0].strip()
                true_exit_code_raw = parts[1].strip()
                
                try:
                    # Capture only the first line/word in case of trailing noise
                    true_exit_code = int(true_exit_code_raw.split()[0])
                except (ValueError, IndexError):
                    true_exit_code = -1 # Format error
                
                return {
                    "exit_code": true_exit_code,
                    "stdout": clean_stdout,
                    "stderr": original_stderr
                }
            
            # Delimiter missing: critical agent failure or older payload
            return {"exit_code": -1, "stdout": raw_stdout.strip(), "stderr": "Echo-Extraction delimiter missing. Agent failure or timeout."}
            
        time.sleep(2)
        timeout -= 2
        
    pending_tasks.pop(target_hostname, None)
    return {"exit_code": -1, "stdout": "", "stderr": "Agent timeout or offline."}

def run_remote_emulation(command, target_hostname, cleanup_command=None, ttp_id=None, target_os="windows", dependencies=None, input_arguments=None, ttp_desc="", ttp_name="", siem_config=None, target_context=None, elevation_required=False, agent_is_privileged=False, test_name=None, test_index=None):
    """Deterministic logic: Success/Fail + SIEM Alerts with Pre-flight Dependencies."""

    current_test_name = test_name or ttp_name or ttp_id
    logs = [f"Starting emulation for {ttp_id} ({current_test_name})..."]
    is_windows = (target_os or "windows").lower() == "windows"

    # 1. TIMING START
    start_time = datetime.now(timezone.utc).isoformat()
    logs.append(f"Execution started at {start_time}")

    stdout_acc = []
    stderr_acc = []
    exit_code = 0
    execution_success = False
    aborted = False
    is_blocked_by_os = False

    try:
        # --- 1. THE PRE-FLIGHT LOOP ---
        if dependencies:
            logs.append("[*] Starting Pre-flight Loop for dependencies...")
            for dep in dependencies:
                desc = dep.get("description", "Dependency")
                prereq_cmd = dep.get("prereq_command")
                fetch_cmd = dep.get("get_prereq_command")

                if not prereq_cmd:
                    continue

                # --- 2. INITIAL CHECK ---
                logs.append(f"[*] Initial Check for: {desc}")
                check_payload = build_staged_payload(prereq_cmd, input_arguments, target_os, target_context, elevation_required=elevation_required)
                result = run_remote_command(check_payload, target_hostname)

                stdout_acc.append(result.get("stdout", ""))
                stderr_acc.append(result.get("stderr", ""))
                return_code = result.get("exit_code", -1)

                # --- 3. EVALUATE & FETCH ---
                if return_code == 0:
                    logs.append(f"[+] Prerequisite already met: {desc}")
                    continue

                logs.append(f"[!] Prerequisite missing: {desc} (Return code: {return_code})")
                if not fetch_cmd:
                    logs.append(f"[X] Dependency '{desc}' is missing and no fetch action is defined. Aborting.")
                    exit_code = return_code
                    aborted = True
                    break

                logs.append(f"[*] Executing Fetch Action for: {desc}")
                fetch_payload = build_staged_payload(fetch_cmd, input_arguments, target_os, target_context, elevation_required=elevation_required)
                result_fetch = run_remote_command(fetch_payload, target_hostname)
                stdout_acc.append(result_fetch.get("stdout", ""))
                stderr_acc.append(result_fetch.get("stderr", ""))

                # --- 4. VERIFICATION (CRITICAL) ---
                logs.append(f"[*] Verifying fetch for: {desc}")
                result_verify = run_remote_command(check_payload, target_hostname) # Re-run initial check
                stdout_acc.append(result_verify.get("stdout", ""))
                stderr_acc.append(result_verify.get("stderr", ""))

                if result_verify.get("exit_code", -1) != 0:
                    logs.append(f"[X] Verification FAILED for '{desc}' after fetch attempt. Return code: {result_verify.get('exit_code')}. Aborting TTP execution.")
                    exit_code = result_verify.get("exit_code", -1)
                    aborted = True
                    break

                logs.append(f"[+] Verification SUCCESS for: {desc}")

        # --- 5. MAIN EXECUTION ---
        if not aborted:
            logs.append("[*] All prerequisites met. Proceeding to Main Execution.")
            main_payload = build_staged_payload(command, input_arguments, target_os, target_context, elevation_required=elevation_required)
            result_main = run_remote_command(main_payload, target_hostname)

            exit_code = result_main.get("exit_code", -1)
            stdout_acc.append(result_main.get("stdout", ""))
            stderr_acc.append(result_main.get("stderr", ""))

            # --- DETERMINISTIC BRAIN: SUCCESS/FAIL EVALUATION ---
            full_output = (result_main.get("stdout", "") + result_main.get("stderr", "")).lower()
            is_blocked_by_os = "password is required" in full_output or "permission denied" in full_output

            if elevation_required and not agent_is_privileged:
                # Execution with lower privileges than required
                if is_windows:
                    # Windows: Expect non-zero exit code or access denied message
                    is_access_denied = "access is denied" in full_output
                    if exit_code != 0 or is_access_denied or is_blocked_by_os:
                        logs.append("[+] Blocked by OS: Test failed as expected due to missing privileges (Windows).")
                        execution_success = True 
                    else:
                        logs.append("[!] Security Gap: Test unexpectedly succeeded despite lack of elevation (Windows).")
                        execution_success = False
                else:
                    # Linux: sudo -n returns 1 if it fails to elevate without password
                    if exit_code == 1 or is_blocked_by_os:
                        logs.append("[+] Blocked by OS: Test failed as expected due to sudo requirement (Linux).")
                        execution_success = True
                    elif exit_code == 0:
                        logs.append("[!] Security Gap: Test unexpectedly succeeded despite lack of elevation (Linux).")
                        execution_success = False
                    else:
                        execution_success = False
            else:
                # Standard execution (either elevation not required OR agent already privileged)
                if is_blocked_by_os and exit_code != 0:
                     logs.append("[+] Blocked by OS: Execution prevented by system permissions.")
                     execution_success = False # It didn't "run", but it was blocked. 
                                              # Note: execution_success=True usually means 'ran successfully' OR 'blocked correctly if elevation was missing'.
                                              # Here, if elevation was NOT required but it was still blocked, it's a failure to run.
                else:
                    execution_success = (exit_code == 0)

            # --- FINAL OVERRIDE FOR SUDO FAILURES ---
            if is_blocked_by_os:
                forced_blocked = True
            else:
                forced_blocked = False

            if execution_success:
                logs.append("[+] Execution Outcome: SUCCESS (either ran fully or was properly blocked by OS).")
            else:
                logs.append(f"[!] Execution Outcome: FAILED (Exit code: {exit_code})")
        else:
            logs.append("[X] Main execution skipped due to pre-flight failure.")

    except Exception as e:
        logs.append(f"[X] Runtime Exception during execution flow: {str(e)}")
        exit_code = -1
    finally:
        # --- 6. GUARANTEED CLEANUP ---
        if cleanup_command:
            logs.append("[*] Starting Guaranteed Cleanup...")
            cleanup_payload = build_staged_payload(cleanup_command, input_arguments, target_os, target_context, elevation_required=elevation_required)
            result_cleanup = run_remote_command(cleanup_payload, target_hostname)
            stdout_acc.append(result_cleanup.get("stdout", ""))
            stderr_acc.append(result_cleanup.get("stderr", ""))
            logs.append("[*] Cleanup finished.")

    end_time = datetime.now(timezone.utc).isoformat()
    logs.append(f"Execution finished at {end_time}")

    # Combine all captured output
    stdout = "\n".join([s for s in stdout_acc if s])
    stderr = "\n".join([s for s in stderr_acc if s])

    # 3. SIEM CHECK
    siem_alerted = False
    wazuh_severity = "0"
    wazuh_rule_desc = "No SIEM alert"
    siem_integrated = siem_config and siem_config.get('enabled')

    if siem_integrated:
        # Mapping hostname to Wazuh Agent ID
        agent_id = "001" if "129" in target_hostname or "kali" in target_hostname.lower() else "000"

        # We need more details from SIEM check now
        wazuh_ip = siem_config.get('ip')
        user = siem_config.get('user')
        password = siem_config.get('password')

        print(f"[*] Waiting 20s for SIEM ingestion...")
        time.sleep(20)

        siem_result = tools.siem_check.check_alerts(ttp_id, agent_id, start_time, end_time, wazuh_ip, user, password, command=command)
        if siem_result.get("alerted"):
            siem_alerted = True
            wazuh_severity = siem_result.get("wazuh_severity", "0")
            wazuh_rule_desc = siem_result.get("wazuh_rule_desc", "Alerted")
            logs.append(f"[+] SIEM Match! Severity: {wazuh_severity} | Desc: {wazuh_rule_desc}")
        else:
            logs.append("[-] No SIEM alerts found for this execution window.")
    else:
        logs.append("SIEM Integration disabled. Skipping detection check.")

    # 4. DETERMINISTIC BRAIN
    sec_status = "Unknown"
    status_run = not aborted
    status_detected = siem_alerted
    remediation = ""

    if is_blocked_by_os:
        sec_status = "Blocked by OS/UAC"
        execution_success = False # User requested this
    elif execution_success:
        if not siem_integrated:
            sec_status = "Execution: Success | Detection: N/A (No SIEM)"
        elif siem_alerted:
            sec_status = "Execution: Success | Detection: ALERTED"
        else:
            sec_status = "Execution: Success | Detection: GAP"
            remediation = f"Advice: Enable auditd monitoring for TTP {ttp_id} or deploy Sysmon for Linux to capture process arguments."
    else:
        # Failed or Blocked (Note: If it was blocked correctly, execution_success is True above)
        if not siem_integrated:
            sec_status = "Execution: Failed | Detection: N/A (No SIEM)"
        elif siem_alerted:
            sec_status = "Execution: Blocked | Detection: PREVENTED"
        else:
            sec_status = "Execution: Failed | Detection: MISSED"

    logs.append(f"Final Verdict: {sec_status}")

    # 5. AI POST-ANALYSIS
    logs.append("[*] Requesting AI Security Analysis from Ollama...")
    ai_reasoning = analyze_test_result(
        ttp_id=ttp_id,
        command=command,
        target_os=target_os,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        wazuh_severity=wazuh_severity,
        wazuh_rule_desc=wazuh_rule_desc,
        test_name=current_test_name,
        ollama_url=siem_config.get('ollama_url', "http://localhost:11434") if siem_config else "http://localhost:11434"
    )
    logs.append(f"[+] AI Reasoning: {ai_reasoning}")

    return {
        "status": "success",
        "sec_status": sec_status,
        "output": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "start_time": start_time,
        "end_time": end_time,
        "status_run": status_run,
        "status_detected": status_detected,
        "remediation": remediation,
        "logs": logs,
        "wazuh_severity": wazuh_severity,
        "wazuh_rule_desc": wazuh_rule_desc,
        "ai_reasoning": ai_reasoning,
        "test_name": current_test_name,
        "test_index": test_index
    }
    