import os
import sys
import time
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, Response, stream_with_context, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests

# Updated custom imports
from tools.atomic_fetcher import fetch_atomic_test
from tools.executor import run_remote_emulation
from tools.db import cti_collection, assets_collection, mitre_info, apt_info
from tools.fetch_otx import smart_fetch_and_store 
from tools.correlator import generate_dynamic_payload
from tools.sequencer import package_context, get_agentic_sequence, apply_sequence_to_work_items
from tools.orchestrator import AIOrchestrator
from tools.shared_state import *

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
# from smolagents import CodeAgent, LiteLLMModel
# from tools.agent_tools import sync_threat_intel, get_target_os, get_atomic_payload, execute_payload, decide_best_technique
import ast
import socket
import psutil
from datetime import datetime, timedelta, timezone
import re

# Updated shared_state import
from tools.shared_state import pending_tasks, agent_results, stop_full_cycle

from dotenv import load_dotenv
load_dotenv()
from sqlalchemy_utils import StringEncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine
import tools.data_ingestor

def _debug_log(hypothesis_id, location, message, data=None, run_id="initial"):
    try:
        payload = {
            "sessionId": "f7f4dc",
            "runId": run_id,
            "hypothesisId": hypothesis_id,
            "location": location,
            "message": message,
            "data": data or {},
            "timestamp": int(time.time() * 1000),
        }
        with open("debug-f7f4dc.log", "a", encoding="utf-8") as _f:
            _f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')
# HF_TOKEN is now loaded from .env

from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Import db and models from tools.models
from tools.models import (
    db, db_encryption_key, Schedule, SimulationResult, TTPMitigation, 
    APTGroup, APTTTP, SoftwareInventory, AtomicTest, AgentSysInfo, 
    AgentPort, IntegrationsConfig, User, SMTPConfig
)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def get_siem_config_dict():
    """Helper to fetch SIEM config for executor."""
    int_config = IntegrationsConfig.query.first()
    return {
        'enabled': int_config.wazuh_enabled if int_config else False,
        'ip': int_config.wazuh_ip if int_config else "",
        'user': int_config.wazuh_user if int_config else "",
        'password': int_config.wazuh_password if int_config else "",
        'ollama_enabled': int_config.ollama_enabled if int_config else False,
        'ollama_url': int_config.ollama_url if int_config else "http://localhost:11434"
    }

with app.app_context():
    db.create_all()
    # Ensure default admin exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        hashed_pw = generate_password_hash('admin', method='pbkdf2:sha256')
        new_admin = User(
            full_name='System Admin', 
            email='admin@beyond-atomics.internal', 
            username='admin', 
            password=hashed_pw, 
            role='admin', 
            status='approved'
        )
        db.session.add(new_admin)
        db.session.commit()
        print("[*] Default admin account created.")
        
    try:
        if not cti_collection.get()['ids']:
            print("[*] Dashboard is empty. Running initial CTI fetch...")
            smart_fetch_and_store()
    except Exception as e:
        print(f"[!] Initial fetch error: {e}")

    # Ingest baseline data if DB is empty
    models = {
        'APTGroup': APTGroup,
        'APTTTP': APTTTP,
        'AtomicTest': AtomicTest,
        'TTPMitigation': TTPMitigation
    }
    # Only ingest if all relevant tables are empty
    if (APTGroup.query.first() is None or
        APTTTP.query.first() is None or
        AtomicTest.query.first() is None or
        TTPMitigation.query.first() is None):
        tools.data_ingestor.check_and_ingest(app, db, models)

def get_ttp_description(ttp_id):
    """Retrieves the MITRE description for a TTP from ChromaDB."""
    try:
        mitre_res = mitre_info.get(where={"id": ttp_id}, include=["documents"])
        if mitre_res and mitre_res['documents']:
            return mitre_res['documents'][0].split('### MITIGATIONS ###')[0].replace('### DESCRIPTION ###', '').strip()
    except Exception as e:
        print(f"Error fetching TTP description: {e}")
    return "No description available."

def find_cti_context_for_ttp(ttp_id):
    """Searches ChromaDB for the CTI pulse that mentions this TTP."""
    try:
        results = cti_collection.get(include=["metadatas", "documents"])
        if not results or not results['metadatas']:
            return "No specific threat intelligence context found for this technique."
            
        for i, meta in enumerate(results['metadatas']):
            ttps = meta.get('technique_id', '')
            if ttp_id in ttps:
                return results['documents'][i]
    except Exception as e:
        print(f"Error finding CTI context: {e}")
            
    return "Technique selected based on general threat landscape analysis."

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('signup'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        # Task 4: Roles removed from signup, default to Analyst/Pending
        new_user = User(
            full_name=full_name, 
            email=email, 
            username=username, 
            password=hashed_password, 
            role='Analyst', 
            status='pending'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration request sent. Please wait for admin approval.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.status != 'approved':
                flash('Your account is pending approval.', 'error')
                return redirect(url_for('login'))
            login_user(user)
            # User requested that login directly opens the dashboard
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile_page():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('password')
        
        user = db.session.get(User, current_user.id)
        if not check_password_hash(user.password, old_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('profile_page'))
            
        if new_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
            db.session.commit()
            flash('Password updated successfully.', 'success')
            return redirect(url_for('profile_page'))
    return render_template('profile.html')

@app.route('/admin/requests')
@login_required
def admin_requests():
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))
    pending_users = User.query.filter_by(status='pending').all()
    # IDs start from 1000 in UI display
    return render_template('admin.html', users=pending_users)

@app.route('/api/schedule/all')
@login_required
def all_schedules():
    schedules = Schedule.query.filter(Schedule.enabled == True).all()
    out = []
    for s in schedules:
        out.append({
            "date": s.run_date,
            "time": s.run_time,
            "hostname": s.target_hostname
        })
    return jsonify(out)

@app.route('/api/admin/approve/<int:user_id>', methods=['POST'])
@login_required
def approve_user(user_id):
    if current_user.role != 'admin':
        return jsonify({"status": "error"}), 403
    user = User.query.get_or_404(user_id)
    user.status = 'approved'
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/api/admin/deny/<int:user_id>', methods=['POST'])
@login_required
def deny_user(user_id):
    if current_user.role != 'admin':
        return jsonify({"status": "error"}), 403
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/api/assets/active')
@login_required
def get_active_assets_api():
    """Returns active assets with OS for UI filtering."""
    targets = get_active_targets()
    return jsonify(targets)

@app.route('/integrations', methods=['GET'])
@login_required
def integrations_page():
    config = IntegrationsConfig.query.first()
    if not config:
        config = IntegrationsConfig()
        db.session.add(config)
        db.session.commit()
    return render_template('integrations.html', config=config)

@app.route('/api/integrations/save', methods=['POST'])
@login_required
def save_integrations():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    config = IntegrationsConfig.query.first()
    if not config:
        config = IntegrationsConfig()
        db.session.add(config)
        
    data = request.json
    config.wazuh_enabled = data.get('wazuh_enabled', False)
    config.wazuh_ip = data.get('wazuh_ip', '')
    config.wazuh_user = data.get('wazuh_user', '')
    if data.get('wazuh_password'):
        config.wazuh_password = data.get('wazuh_password')
        
    config.otx_api_key = data.get('otx_api_key', '')
    
    config.ollama_enabled = data.get('ollama_enabled', False)
    config.ollama_url = data.get('ollama_url', '')
    config.ollama_model = data.get('ollama_model', '')
    
    db.session.commit()
    return jsonify({"status": "success", "message": "Integrations saved successfully."})

@app.route('/api/integrations/wazuh/test', methods=['POST'])
@login_required
def test_wazuh_connection():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    data = request.json
    ip = data.get('ip')
    user = data.get('user')
    password = data.get('password')
    
    if not ip or not user or not password:
        return jsonify({"status": "error", "message": "IP, User, and Password are required."})
        
    token = tools.executor.get_wazuh_token(ip, user, password)
    if token:
        return jsonify({"status": "success", "message": "Successfully authenticated with Wazuh API!"})
    else:
        return jsonify({"status": "error", "message": "Failed to authenticate. Check IP and credentials."})

@app.route('/api/integrations/otx/test', methods=['POST'])
@login_required
def test_otx_connection():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    data = request.json
    key = data.get('key')
    if not key:
        return jsonify({"status": "error", "message": "API Key is required."})
        
    try:
        from OTXv2 import OTXv2
        otx = OTXv2(key)
        # Try a simple lightweight call
        pulses = otx.get_pulses_subscribed(limit=1)
        return jsonify({"status": "success", "message": "OTX API Key validated successfully!"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Validation failed: {str(e)}"})

@app.route('/api/integrations/status')
@login_required
def get_integrations_status():
    config = IntegrationsConfig.query.first()
    return jsonify({
        "wazuh_enabled": config.wazuh_enabled if config else False,
        "otx_enabled": bool(config.otx_api_key) if config else False,
        "ollama_enabled": config.ollama_enabled if config else False
    })

@app.route('/api/integrations/ollama/models')
@login_required
def get_ollama_models():
    config = IntegrationsConfig.query.first()
    url = config.ollama_url if config and config.ollama_url else "http://localhost:11434"
    try:
        r = requests.get(f"{url}/api/tags", timeout=5)
        if r.status_code == 200:
            models = [m['name'] for m in r.json().get('models', [])]
            return jsonify({"status": "success", "models": models})
        return jsonify({"status": "error", "message": f"Ollama returned status {r.status_code}"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Could not connect to Ollama: {str(e)}"})

@app.route('/api/integrations/ollama/test', methods=['POST'])
@login_required
def test_ai_connection():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    data = request.json
    url = data.get('url', 'http://localhost:11434')
    model = data.get('model', 'phi3')
    
    try:
        # Simple generation request to test readiness
        payload = {
            "model": model,
            "prompt": "Say 'ready'",
            "stream": False,
            "max_tokens": 5
        }
        r = requests.post(f"{url}/api/generate", json=payload, timeout=10)
        if r.status_code == 200:
            return jsonify({"status": "success", "message": f"AI model '{model}' is ready and responding!"})
        else:
            return jsonify({"status": "error", "message": f"Ollama returned error: {r.text}"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Connection failed: {str(e)}"})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    threats_data = cti_collection.get(limit=5, include=["metadatas", "documents"])
    latest_threats = []
    if threats_data and threats_data['metadatas']:
        for i in range(len(threats_data['metadatas'])):
            latest_threats.append({
                "title": threats_data['documents'][i].split('\n')[0].replace('Title: ', ''),
                "ttps": threats_data['metadatas'][i].get('technique_id', 'None')
            })
    return render_template('index.html', technique_id="Security Overview", threats=latest_threats)

def get_target_ttps(target_hostname=None):
    """
    Returns TTPs specifically mapped to the keyword of the target asset.
    """
    import re as _re
    assets = assets_collection.get(include=["metadatas"])
    if not assets['metadatas']:
        return [], "unknown", "Unknown"
        
    target_meta = None
    for meta in assets['metadatas']:
        if meta.get('hostname') == target_hostname:
            target_meta = meta
            break
            
    if not target_meta:
        target_meta = assets['metadatas'][0]
        
    actual_hostname = target_meta.get('hostname', 'Unknown')
    actual_os = target_meta.get('os', 'unknown').lower()
    
    machine_keywords = [actual_os]
    prereqs = target_meta.get('known_prereqs', '')
    if prereqs:
        machine_keywords.extend([p.strip().lower() for p in prereqs.split(',') if p.strip()])

    cti_data = cti_collection.get(include=["metadatas"])
    candidate_ttps = []
    
    for meta in cti_data.get('metadatas', []):
        target_keyword_str = meta.get('target_keyword', '').lower()
        # Split keywords in metadata (e.g. "windows, linux") and check against machine keywords
        meta_keywords = [k.strip() for k in target_keyword_str.split(',') if k.strip()]
        
        if any(k in machine_keywords for k in meta_keywords):
            ttp_string = meta.get('technique_id', '')
            found = _re.findall(r'T\d{4}(?:\.\d{3})?', ttp_string)
            for t in found:
                if t not in candidate_ttps:
                    candidate_ttps.append(t)
                    
    return candidate_ttps, actual_os, actual_hostname


def pretty_os_label(os_raw):
    """Short OS label for dispatch UI (e.g. Win / Linux)."""
    o = (os_raw or "unknown").lower()
    if "win" in o:
        return "Win"
    if "linux" in o or o == "linux":
        return "Linux"
    s = (os_raw or "Unknown").strip()
    return s if s else "Unknown"


def get_active_targets():
    """
    Assets seen within the last 120s (same rule as /assets), each with
    candidate TTPs from threat intel for that host (via get_target_ttps).
    """
    assets = assets_collection.get(include=["metadatas"])
    if not assets.get("metadatas"):
        return []
    now = datetime.now(timezone.utc)
    out = []
    for meta in assets["metadatas"]:
        last_seen_str = meta.get("last_seen")
        if not last_seen_str:
            continue
        try:
            last_seen = datetime.fromisoformat(last_seen_str)
            if (now - last_seen).total_seconds() >= 120:
                continue
        except Exception:
            continue
        hostname = meta.get("hostname")
        if not hostname:
            continue
        ttps, actual_os, actual_hostname = get_target_ttps(hostname)
        out.append({
            "hostname": actual_hostname,
            "os": actual_os,
            "ttps": ttps,
        })
    return out


@app.route('/api/target-ttps')
@login_required
def target_ttps_api():
    """
    Returns the list of techniques the tool intends to test on this device,
    enriched with their MITRE names for display in the Heatmap.
    """
    ttps, target_os, target_hostname = get_target_ttps()
    enriched = []
    for ttp_id in ttps:
        mitre_result = mitre_info.get(where={"id": ttp_id}, include=["metadatas"])
        name = mitre_result['metadatas'][0]['name'] if mitre_result and mitre_result['metadatas'] else ttp_id
        enriched.append({"id": ttp_id, "name": name})
    return jsonify({"target_os": target_os, "target_hostname": target_hostname, "ttps": enriched})


@app.route('/api/mitre-stats')
@login_required
def mitre_stats():
    try:
        # 1. Start with CTI-based TTPs
        target_ttps, target_os, target_hostname = get_target_ttps()
        heatmap_ttp_ids = set()
        for t in target_ttps:
            if t: heatmap_ttp_ids.add(str(t))

        # 2. Add TTPs from Simulation Results (Scoreboard)
        results = SimulationResult.query.all()
        tested_data = {}
        for r in results:
            if not r.ttp_id: continue
            ttp_id = str(r.ttp_id)
            heatmap_ttp_ids.add(ttp_id)
            
            status_low = (r.status or "").lower()
            if 'prevented' in status_low or status_low == 'skipped':
                color = "rgba(255,255,255,0.1)" # Gray/Skipped
                status_label = "Skipped"
            elif r.status_detected:
                color = "#22c55e"      # green for ALERTED
                status_label = "Alerted"
            else:
                # For 'missed' or anything else not detected, treat as GAP
                color = "#f59e0b"
                status_label = "GAP"
                
            tested_data[ttp_id] = {
                "status": status_label,
                "color": color,
                "name": r.ttp_name or ttp_id
            }

        # 3. Add TTPs from Schedules (Planned)
        scheduled_ttp_ids = set()
        schedules = Schedule.query.filter_by(enabled=True).all()
        for s in schedules:
            if s.ttp_id:
                tid = str(s.ttp_id)
                heatmap_ttp_ids.add(tid)
                scheduled_ttp_ids.add(tid)

        # 4. Enforce canonical sorting for the heatmap
        valid_ttp_ids = [t for t in heatmap_ttp_ids if isinstance(t, str) and t.strip()]
        sorted_ttps = sorted(valid_ttp_ids)

        heatmap_data = {}
        for ttp_id in sorted_ttps:
            if ttp_id in tested_data:
                heatmap_data[ttp_id] = tested_data[ttp_id]
            else:
                # Not tested, either CTI-discovered or manually planned
                try:
                    mitre_result = mitre_info.get(where={"id": ttp_id}, include=["metadatas"])
                    if mitre_result and mitre_result.get('metadatas'):
                        name = mitre_result['metadatas'][0].get('name', ttp_id)
                    else:
                        name = ttp_id
                except:
                    name = ttp_id
                
                # Use a more visible color for Planned/Scheduled
                status_label = "Planned"
                color = "rgba(255,255,255,0.06)" # Default CTI planned
                
                if ttp_id in scheduled_ttp_ids:
                    status_label = "Planned" # Keep label consistent with legend
                    color = "rgba(148, 163, 184, 0.2)" # More visible for explicitly scheduled
                    
                heatmap_data[ttp_id] = {
                    "status": status_label,
                    "color": color,
                    "name": name
                }
        return jsonify(heatmap_data)
    except Exception as e:
        print(f"ERROR in mitre_stats: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({}), 500

@app.route('/scoreboard')
@login_required
def scoreboard():
    results = SimulationResult.query.order_by(SimulationResult.timestamp.desc()).all()
    total_tests = len(results)
    alerted_tests = 0
    detections_gap = 0
    
    for r in results:
        if r.status_detected:
            alerted_tests += 1
        else:
            detections_gap += 1

    # Score is % of tests that were Alerted (higher is better for detection posture)
    score = int((alerted_tests / total_tests * 100)) if total_tests > 0 else 100
    return render_template('scoreboard.html', 
                           results=results, 
                           score=score, 
                           total=total_tests, 
                           vulnerable=detections_gap,
                           detections_gap=detections_gap)

@app.route('/export/scoreboard')
@login_required
def export_scoreboard():
    results = SimulationResult.query.order_by(SimulationResult.timestamp.desc()).all()
    csv_data = "Date,Target Host,TTP ID,Technique Name,Outcome\n"
    for r in results:
        clean_name = r.ttp_name.replace(',', ';')
        csv_data += f"{r.timestamp.strftime('%Y-%m-%d %H:%M:%S')},{r.target_hostname},{r.ttp_id},{clean_name},{r.status}\n"
    return Response(csv_data, mimetype="text/csv", headers={"Content-disposition": "attachment; filename=security_posture_report.csv"})

def get_vmnet_ip():
    interfaces = psutil.net_if_addrs()
    
    # Prioritize VMware interfaces
    for interface_name, snics in interfaces.items():
        if "vmware" in interface_name.lower() or "vmnet" in interface_name.lower():
            for snic in snics:
                if snic.family == socket.AF_INET:
                    if not snic.address.startswith("127."):
                        return snic.address
                        
    # Fallback to the original logic
    for interface_name, snics in interfaces.items():
        for snic in snics:
            if snic.family == socket.AF_INET:
                if snic.address.startswith("192.168.") or snic.address.startswith("10.") or snic.address.startswith("172."):
                    if not snic.address.startswith("127."):
                        return snic.address
    return socket.gethostbyname(socket.gethostname())

@app.route('/assets')
@login_required
def assets():
    target_c2_ip = get_vmnet_ip()
    assets_data = assets_collection.get(include=["metadatas", "documents"])
    asset_list = []
    
    if assets_data and assets_data['metadatas']:
        for i in range(len(assets_data['metadatas'])):
            meta = assets_data['metadatas'][i]
            hostname = meta.get('hostname', 'Unknown')
            
            status = "Offline"
            last_seen_str = meta.get('last_seen')
            if last_seen_str:
                try:
                    last_seen = datetime.fromisoformat(last_seen_str)
                    if (datetime.now(timezone.utc) - last_seen).total_seconds() < 120:
                        status = "Online"
                except Exception:
                    pass

            # Fetch extra info from DB
            sysinfo = AgentSysInfo.query.filter_by(hostname=hostname).first()
            ports = AgentPort.query.filter_by(hostname=hostname).all()

            asset_item = meta.copy()
            asset_item.update({
                "status": status,
                "details": assets_data['documents'][i],
                "sysinfo": {
                    "cpu": sysinfo.cpu if sysinfo else "Unknown",
                    "ram": sysinfo.ram if sysinfo else "Unknown",
                    "storage": sysinfo.storage if sysinfo else "Unknown",
                    "os_version": sysinfo.os_version if sysinfo else "Unknown"
                },
                "ports": [{"port": p.port, "protocol": p.protocol} for p in ports]
            })
            asset_list.append(asset_item)
            
    return render_template('assets.html', assets=asset_list, server_ip=target_c2_ip)

@app.route('/api/payload/<path:filepath>')
def download_payload(filepath):
    """Serves prerequisite payload files for TTP execution."""
    directory = os.path.join(app.root_path, 'atomics')
    try:
        return send_from_directory(directory, filepath)
    except FileNotFoundError:
        return Response("File not found", status=404)

@app.route('/api/agent/<hostname>/delete', methods=['POST'])
@login_required
def delete_agent(hostname):
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    try:
        # 1. Remove from ChromaDB
        assets_collection.delete(ids=[f"target_{hostname}"])
        
        # 2. Remove from SQL Tables
        AgentSysInfo.query.filter_by(hostname=hostname).delete()
        AgentPort.query.filter_by(hostname=hostname).delete()
        SoftwareInventory.query.filter_by(hostname=hostname).delete()
        
        db.session.commit()
        return jsonify({"status": "success", "message": f"Agent {hostname} removed successfully."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/scripts/<platform>', methods=['GET'])
def distributed_agent_script(platform):
    # Use request.host to be much more robust (it's the IP/Port the agent actually used to connect)
    server_url = f"http://{request.host}"

    if platform == 'win':
        script_body = render_template('agent.ps1', server_url=server_url)
        return Response(script_body, mimetype='text/plain')

    if platform == 'linux':
        script_body = render_template('agent.sh', server_url=server_url)
        return Response(script_body, mimetype='text/plain')

    return Response("Unsupported platform", status=404, mimetype='text/plain')

@app.route('/remediation/<ttp_id>')
def remediation(ttp_id):
    _debug_log(
        "H1",
        "app.py:remediation:entry",
        "Entered remediation route",
        {"ttp_id": ttp_id},
    )
    
    # Try to get the name from the AtomicTest table or mitre_info
    technique_name = ttp_id
    test = AtomicTest.query.filter_by(ttp_id=ttp_id).first()
    if test and test.ttp_name:
        technique_name = test.ttp_name
    else:
        results = mitre_info.get(where={"id": ttp_id}, include=["metadatas"])
        if results and results.get('metadatas'):
            technique_name = results['metadatas'][0].get('name', ttp_id)
            
    # Fetch mitigations from the database
    mitigations = TTPMitigation.query.filter_by(ttp_id=ttp_id).all()

    return render_template(
        'remediation.html',
        ttp_id=ttp_id,
        name=technique_name,
        mitigations=mitigations
    )

@app.route('/telemetry/<int:sim_id>')
@login_required
def telemetry(sim_id):
    sim = SimulationResult.query.get_or_404(sim_id)
    return render_template('telemetry.html', sim=sim)

COMMON_PREREQS = ['python', 'python3', 'node', 'java', 'docker', 'gcc', 'perl', 'ruby', 'curl', 'wget']
import ipaddress

def classify_asset(ip, open_ports, os_version=""):
    """
    Deterministically classifies the asset based on IP, open ports, and OS version.
    Categories: User Workstation, Internal Server, Public Facing Server.
    """
    os_ver = (os_version or "").lower()
    
    # 1. OS-based heuristic
    is_server_os = any(k in os_ver for k in ["server", "windows server", "enterprise", "ubuntu server", "rhel", "centos", "debian"])
    is_workstation_os = any(k in os_ver for k in ["windows 10", "windows 11", "pro", "home", "macos", "workstation"])

    # 2. Port-based heuristic (Standard Server Ports)
    server_ports = {
        '80', '443',      # Web
        '22', '23',       # Management (SSH, Telnet)
        '21',             # FTP
        '25', '110', '143', '993', '995', # Mail
        '53',             # DNS
        '3306', '5432', '1433', '1521', '27017', '6379', # DB
        '8080', '8443',   # App Servers
        '161',            # SNMP
    }
    has_server_ports = any(p in server_ports for p in open_ports)

    # 3. IP Locality
    is_public = False
    try:
        ip_obj = ipaddress.ip_address(ip)
        is_public = not ip_obj.is_private and not ip_obj.is_loopback and not ip_obj.is_link_local
    except:
        pass

    # Logic tree:
    if is_public and (has_server_ports or is_server_os):
        return "Public Facing Server"
    
    if is_server_os or has_server_ports:
        return "Internal Server"
        
    if is_workstation_os:
        return "User Workstation"
        
    # Default fallback
    return "User Workstation" if not has_server_ports else "Internal Server"

@app.route('/api/checkin', methods=['POST'])
def agent_checkin():
    data = request.json
    hostname = data.get('hostname')
    is_privileged = data.get('is_privileged', False)
    existing = assets_collection.get(ids=[f"target_{hostname}"])

    # Update last seen and privilege status
    if existing and existing['ids']:
        meta = existing['metadatas'][0]
        meta['last_seen'] = datetime.now(timezone.utc).isoformat()
        meta['is_privileged'] = is_privileged
        meta['ip'] = request.remote_addr
        assets_collection.update(ids=existing['ids'], metadatas=[meta])
    else:
        # Initial asset creation
        meta = {
            "hostname": hostname,
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "is_privileged": is_privileged,
            "ip": request.remote_addr
        }
        assets_collection.add(ids=[f"target_{hostname}"], metadatas=[meta], documents=[f"Asset: {hostname}"])

    # Force recon if:
    # 1. New asset
    # 2. No sysinfo found
    # 3. No software inventory found
    # 4. MISSING classification
    has_sysinfo = AgentSysInfo.query.filter_by(hostname=hostname).first() is not None
    has_software = SoftwareInventory.query.filter_by(hostname=hostname).first() is not None
    has_classification = existing['ids'] and existing['metadatas'][0].get('asset_classification')
    
    if not existing['ids'] or not has_sysinfo or not has_software or not has_classification:
        if data.get('os') == 'win':
            recon_cmd = (
                "echo '[OS]' ; (Get-CimInstance Win32_OperatingSystem).Caption + ' ' + (Get-CimInstance Win32_OperatingSystem).Version ; "
                "echo '[USER]' ; whoami ; "
                "echo '[DOMAIN]' ; (Get-CimInstance Win32_ComputerSystem).Domain ; "
                "echo '[ARCH]' ; $env:PROCESSOR_ARCHITECTURE ; "
                "echo '[SYSINFO]' ; "
                "$cpu = (Get-CimInstance Win32_Processor).Name; "
                "$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2); "
                "$disk = (Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DeviceID -eq 'C:' }); "
                "$storage = [math]::Round($disk.Size / 1GB, 2).ToString() + 'GB Total, ' + [math]::Round($disk.FreeSpace / 1GB, 2).ToString() + 'GB Free'; "
                "echo \"CPU: $cpu\" ; echo \"RAM: $ram GB\" ; echo \"Storage: $storage\" ; "
                "echo '[PORTS]' ; Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess | ConvertTo-Json -Compress ; "
                "echo '[SOFTWARE]' ; "
                "$paths = @('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', 'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
                "foreach ($p in $paths) { Get-ItemProperty $p -ErrorAction SilentlyContinue | ForEach-Object { if ($_.DisplayName) { echo \"$($_.DisplayName)|$($_.DisplayVersion)\" } } }; "
                "echo '[PREREQS]' ; $tools = @('python','python3','node','java','docker','gcc','perl','ruby','curl','wget','git','go','rustc'); foreach ($t in $tools) { if (Get-Command $t -ErrorAction SilentlyContinue) { echo $t } }"
            )
        else:
            recon_cmd = (
                "echo '[OS]' ; grep PRETTY_NAME /etc/os-release | cut -d '=' -f 2 | tr -d '\"' ; "
                "echo '[USER]' ; whoami ; "
                "echo '[DOMAIN]' ; hostname -d || echo 'Local' ; "
                "echo '[ARCH]' ; uname -m ; "
                "echo '[SYSINFO]' ; "
                "echo -n 'CPU: ' ; lscpu | grep 'Model name' | cut -d ':' -f 2 | xargs ; "
                "echo -n 'RAM: ' ; free -h | grep Mem | awk '{print $2}' ; "
                "echo -n 'Storage: ' ; df -h / | awk 'NR==2 {print $2 \" Total, \" $4 \" Free\"}' ; "
                "echo '[PORTS]' ; ss -tulnp | awk 'NR>1 {print $4}' | cut -d ':' -f 2 | sort -u ; "
                "echo '[SOFTWARE]' ; "
                "if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package}|${Version}\\n'; elif command -v rpm >/dev/null 2>&1; then rpm -qa --queryformat '%{NAME}|%{VERSION}\\n'; fi ; "
                "echo '[PREREQS]' ; for cmd in python python3 node java docker gcc perl ruby curl wget git go rustc; do command -v $cmd >/dev/null 2>&1 && echo $cmd; done"
            )
        return jsonify({"status": "task", "command": recon_cmd})

    if hostname in pending_tasks:
        command = pending_tasks.pop(hostname)
        return jsonify({"status": "task", "command": command})

    return jsonify({"status": "sleep"})

def get_ttp_safety_categorization(ttp_id, name, description, command):
    """(AI DISABLED) Uses local Phi3 via Ollama to analyze TTP risk."""
    # try:
    #     url = "http://localhost:11434/api/generate"
    #     prompt = f"""You are a Cyber Security Safety Auditor.
    # Analyze this TTP and determine if it is destructive.
    # NAME: {name}
    # DESCRIPTION: {description}
    # COMMAND: {command}
    # 
    # CATEGORIES:
    # - Safe: Read-only, informational, or very minor non-persistent changes.
    # - Modifying: Configuration changes, persistence, or adding files (non-destructive but changes state).
    # - Destructive: Deletes data, stops critical services, reboots/shuts down system, or locks account.
    # 
    # Respond ONLY with a JSON object:
    # {{
    #   "category": "Safe" | "Modifying" | "Destructive",
    #   "reason": "short explanation",
    #   "risk_score": 1-10
    # }}
    # """
    #     payload = {
    #         "model": "phi3",
    #         "prompt": prompt,
    #         "stream": False,
    #         "format": "json"
    #     }
    #     response = requests.post(url, json=payload, timeout=120)
    #     if response.status_code == 200:
    #         result = json.loads(response.json().get('response', '{}'))
    #         return result
    # except Exception as e:
    #     print(f"Error calling Ollama for safety check: {e}")
    
    return {"category": "Safe", "reason": "AI analysis disabled. Defaulting to Safe.", "risk_score": 0}

@app.route('/api/ttp/safety/<ttp_id>')
@login_required
def ttp_safety_api(ttp_id):
    # Try to find TTP info
    mitre_res = mitre_info.get(where={"id": ttp_id}, include=["metadatas", "documents"])
    if not mitre_res or not mitre_res['ids']:
        return jsonify({"error": "TTP not found"}), 404
        
    name = mitre_res['metadatas'][0].get('name')
    doc = mitre_res['documents'][0]
    description = doc.split('### MITIGATIONS ###')[0].replace('### DESCRIPTION ###', '').strip()
    
    # Get command from atomic cache
    cache_path = os.path.join("one_time_usage_files", "atomic_cache.json")
    command = "Unknown"
    if os.path.exists(cache_path):
        with open(cache_path, 'r', encoding='utf-8') as f:
            cache = json.load(f)
            if ttp_id in cache:
                # We'll just take the first test's command for analysis
                # Ideally we analyze all, but for now this works
                raw_test = fetch_atomic_test(ttp_id, "windows") # Default to win for check
                if raw_test and 'test' in raw_test:
                    command = raw_test['test']['executor'].get('command', 'Unknown')

    safety = get_ttp_safety_categorization(ttp_id, name, description, command)
    return jsonify(safety)

@app.route('/api/results', methods=['POST'])
def agent_results_endpoint():
    data = request.json
    hostname = data.get('hostname')
    output = data.get('output', '')
    exit_code = data.get('exit_code', 0)
    stderr = data.get('stderr', '')

    # Robust type-checking: Ensure output and stderr are always strings
    if isinstance(output, (dict, list)):
        output = json.dumps(output)
    elif output is None:
        output = ""
    else:
        output = str(output)

    if isinstance(stderr, (dict, list)):
        stderr = json.dumps(stderr)
    elif stderr is None:
        stderr = ""
    else:
        stderr = str(stderr)
    
    agent_results[hostname] = {
        "exit_code": exit_code,
        "stdout": output,
        "stderr": stderr
    }
    output_lower = output.lower()

    if "[os]" in output_lower:
        # 1. Parse OS strictly from [OS] block
        detected_os = "linux"
        try:
            os_parts = re.split(r'\[OS\]', output, flags=re.IGNORECASE)
            if len(os_parts) > 1:
                os_line = os_parts[1].split('[')[0].strip().lower()
                if "windows" in os_line:
                    detected_os = "windows"
        except Exception:
            pass

        # 2. Parse New Security Context Blocks
        current_user_val = "Unknown"
        domain_val = "Local"
        arch_val = "Unknown"
        
        try:
            user_parts = re.split(r'\[USER\]', output, flags=re.IGNORECASE)
            if len(user_parts) > 1: current_user_val = user_parts[1].split('[')[0].strip()
            
            domain_parts = re.split(r'\[DOMAIN\]', output, flags=re.IGNORECASE)
            if len(domain_parts) > 1: domain_val = domain_parts[1].split('[')[0].strip()
            
            arch_parts = re.split(r'\[ARCH\]', output, flags=re.IGNORECASE)
            if len(arch_parts) > 1: arch_val = arch_parts[1].split('[')[0].strip()
        except Exception: pass

        # 3. Security Tools Specifics
        security_tools_map = {
            'defender': 'Windows Defender',
            'msmpeng': 'Windows Defender',
            'sysmon': 'Sysmon',
            'crowdstrike': 'CrowdStrike Falcon',
            'sentinel': 'SentinelOne',
            'apparmor': 'AppArmor',
            'selinux': 'SELinux',
            'wazuh': 'Wazuh Agent',
            'firewalld': 'Firewalld',
            'iptables': 'IPtables'
        }
        detected_tools = []
        for key, display in security_tools_map.items():
            if key in output_lower:
                if display not in detected_tools:
                    detected_tools.append(display)
        
        has_security_tools = 'true' if detected_tools else 'false'
        tools_str = ", ".join(detected_tools) if detected_tools else "None"

        # 4. Parse System Info
        sysinfo_data = {"cpu": "Unknown", "ram": "Unknown", "storage": "Unknown", "os_version": "Unknown"}
        try:
            sys_parts = re.split(r'\[SYSINFO\]', output, flags=re.IGNORECASE)
            if len(sys_parts) > 1:
                sys_section = sys_parts[1].split('[')[0].strip()
                for line in sys_section.split('\n'):
                    if ':' in line:
                        key, val = line.split(':', 1)
                        key = key.strip().lower()
                        if key == 'cpu': sysinfo_data['cpu'] = val.strip()
                        elif key == 'ram': sysinfo_data['ram'] = val.strip()
                        elif key == 'storage': sysinfo_data['storage'] = val.strip()
            
            # OS Version from [OS] block
            os_parts = re.split(r'\[OS\]', output, flags=re.IGNORECASE)
            if len(os_parts) > 1:
                sysinfo_data['os_version'] = os_parts[1].split('[')[0].strip()
        except Exception:
            pass
        
        # Save System Info
        AgentSysInfo.query.filter_by(hostname=hostname).delete()
        new_sys = AgentSysInfo(
            hostname=hostname,
            os_version=sysinfo_data['os_version'],
            cpu=sysinfo_data['cpu'],
            ram=sysinfo_data['ram'],
            storage=sysinfo_data['storage']
        )
        db.session.add(new_sys)

        # 5. Parse Ports
        ports_list = []
        try:
            port_parts = re.split(r'\[PORTS\]', output, flags=re.IGNORECASE)
            if len(port_parts) > 1:
                port_section = port_parts[1].split('[')[0].strip()
                if detected_os == "windows":
                    # Parse JSON from Windows Get-NetTCPConnection
                    try:
                        entries = json.loads(port_section)
                        if isinstance(entries, list):
                            for entry in entries:
                                ports_list.append((str(entry.get('LocalPort')), "TCP", "Unknown"))
                        elif isinstance(entries, dict):
                            ports_list.append((str(entries.get('LocalPort')), "TCP", "Unknown"))
                    except: pass
                else:
                    # Linux ss output (just list of ports for now)
                    for line in port_section.split('\n'):
                        p = line.strip()
                        if p.isdigit():
                            ports_list.append((p, "TCP/UDP", "Unknown"))
        except Exception:
            pass
        
        # Save Ports
        AgentPort.query.filter_by(hostname=hostname).delete()
        for p_num, proto, svc in ports_list:
            if p_num:
                new_port = AgentPort(hostname=hostname, port=p_num, protocol=proto, service_name=svc)
                db.session.add(new_port)

        # 6. Parse Software & Prereqs
        software_list = []
        # Normal Software
        try:
            sw_parts = re.split(r'\[SOFTWARE\]', output, flags=re.IGNORECASE)
            if len(sw_parts) > 1:
                sw_section = sw_parts[1].split('[')[0].strip()
                # Parse line-based Name|Version format
                for line in sw_section.split('\n'):
                    line = line.strip()
                    if '|' in line:
                        parts = line.split('|')
                        if len(parts) >= 1:
                            name = parts[0].strip()
                            version = parts[1].strip() if len(parts) > 1 else "---"
                            if name:
                                software_list.append((name, version))
        except Exception as e:
            print(f"Error parsing software: {e}")

        # Prereqs as Software
        try:
            pre_parts = re.split(r'\[PREREQS\]', output, flags=re.IGNORECASE)
            if len(pre_parts) > 1:
                pre_section = pre_parts[1].strip()
                for line in pre_section.split('\n'):
                    tool = line.strip()
                    if tool: software_list.append((f"Tool: {tool}", "Installed"))
        except Exception: pass

        # Perform Asset Classification
        asset_ip = request.remote_addr
        open_port_numbers = [p[0] for p in ports_list]
        classification = classify_asset(asset_ip, open_port_numbers, sysinfo_data['os_version'])

        # Save Software
        SoftwareInventory.query.filter_by(hostname=hostname).delete()
        for name, version in software_list:
            new_sw = SoftwareInventory(hostname=hostname, software_name=name, version=version)
            db.session.add(new_sw)
        
        db.session.commit()

        # Update ChromaDB Asset
        assets_collection.upsert(
            documents=[output],
            metadatas=[{
                "type": "target_machine",
                "os": detected_os,
                "hostname": hostname,
                "ip": asset_ip,
                "status": "active",
                "is_admin": 'false', # Forced normal user
                "has_security_tools": has_security_tools,
                "detected_tools": tools_str,
                "current_user": current_user_val,
                "domain": domain_val,
                "arch": arch_val,
                "asset_classification": classification,
                "known_prereqs": ",".join([s[0].replace("Tool: ", "") for s in software_list if s[0].startswith("Tool:")])
            }],
            ids=[f"target_{hostname}"]
        )
        print(f"[+] Saved baseline for {hostname} (OS: {detected_os.upper()}, User: {current_user_val}, Tools: {tools_str})")
        return jsonify({"status": "received", "type": "recon"})
    return jsonify({"status": "received", "type": "task"})

def generate_safe_preflight_check(os_type, requested_software):
    """
    Takes the AI's requested software, sanitizes it, and wraps it in a safe execution block.
    """
    safe_target = re.sub(r'[^a-zA-Z0-9\-]', '', requested_software.strip().lower())
    
    if not safe_target:
        return None

    if os_type == 'windows':
        safe_cmd = f"if (Get-Command {safe_target} -ErrorAction SilentlyContinue) {{ echo 'PREFLIGHT_FOUND_{safe_target}' }} else {{ echo 'PREFLIGHT_NOTFOUND_{safe_target}' }}"
    else:
        safe_cmd = f"command -v {safe_target} >/dev/null 2>&1 && echo 'PREFLIGHT_FOUND_{safe_target}' || echo 'PREFLIGHT_NOTFOUND_{safe_target}'"
        
    return safe_cmd


# def ai_agentic_loop(hostname, llm_json_response):
#     
#     if llm_json_response.get("action") == "check_software":
#         target_software = llm_json_response.get("target")
#         
#         asset = assets_collection.get(ids=[f"target_{hostname}"], include=["metadatas"])
#         known_prereqs = asset['metadatas'][0].get('known_prereqs', '')
#         
#         if target_software in known_prereqs.split(','):
#             print(f"AI asked for {target_software}. Cache hit. Proceeding.")
#             return
#             
#         os_type = asset['metadatas'][0].get('os')
#         safe_cmd = generate_safe_preflight_check(os_type, target_software)
#         
#         pending_tasks[hostname] = safe_cmd
#         print(f"Queued Safe Live Check for {target_software} on {hostname}")

def build_target_context(hostname):
    """Builds a dictionary of target-specific facts for variable interpolation."""
    inventory = SoftwareInventory.query.filter_by(hostname=hostname).all()
    sysinfo = AgentSysInfo.query.filter_by(hostname=hostname).first()
    
    context = {s.software_name.lower(): s.version for s in inventory}
    if sysinfo:
        context.update({
            "os_version": sysinfo.os_version,
            "cpu": sysinfo.cpu,
            "ram": sysinfo.ram,
            "storage": sysinfo.storage,
            "hostname": hostname
        })
    return context

@app.route('/api/autopilot', methods=['POST'])
@login_required
def run_autopilot():
    """
    AI-Orchestrated Group Execution for a specific host.
    """
    try:
        data = request.json or {}
        target_hostname = data.get('hostname')
        requested_test_guid = data.get('test_guid')
        
        if not target_hostname:
             return jsonify({"status": "error", "output": "No hostname provided."})

        config = IntegrationsConfig.query.first()
        ollama_url = config.ollama_url if config and config.ollama_url else "http://localhost:11434"
        orchestrator = AIOrchestrator(ollama_url=ollama_url)

        if requested_test_guid:
            return run_manual_ttp()

        # Orchestrate Group
        candidate_ttps, actual_os, actual_hostname = get_target_ttps(target_hostname)
        if not candidate_ttps:
            return jsonify({"status": "skip", "output": "No TTPs mapped to this target."})

        # Process the generator to execute everything
        results = []
        for evt in orchestrator.orchestrate_group_execution(target_hostname, candidate_ttps[:10]):
            if evt['event'] == 'result':
                results.append(evt)

        return jsonify({"status": "complete", "message": "AI-Orchestrated group execution finished.", "results": results})
        
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"status": "error", "output": str(e)}), 500
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"status": "error", "output": str(e)}), 500

@app.route('/api/cti/feed', methods=['GET'])
@login_required
def get_cti_feed():
    """Returns the latest threat intelligence for the frontend Dashboard"""
    cti_data = cti_collection.get(limit=10, include=["metadatas", "documents"])
    feed = []
    if cti_data and cti_data.get('metadatas'):
        for i, meta in enumerate(cti_data['metadatas']):
            # Robust title extraction
            title = meta.get('title')
            if not title:
                # Fallback to parsing from document if metadata title is missing (for old entries)
                doc = cti_data['documents'][i]
                if "Title: " in doc:
                    title = doc.split('\n')[0].replace('Title: ', '')
                else:
                    title = "Recent Threat Activity"
            
            # Full description extraction (removing the Title line)
            full_doc = cti_data['documents'][i]
            description = full_doc
            if "Description: " in full_doc:
                description = full_doc.split('Description: ', 1)[1]
            elif "\n" in full_doc:
                description = full_doc.split('\n', 1)[1]

            feed.append({
                "title": title,
                "source": meta.get('source'),
                "keyword": meta.get('target_keyword'),
                "techniques": meta.get('technique_id'),
                "description": description
            })
    return jsonify(feed)

def check_software_prerequisites(hostname, dependencies, command):
    """Checks if the agent has the necessary software to run the TTP."""
    common_engines = ['python', 'python3', 'node', 'java', 'docker', 'gcc', 'perl', 'ruby', 'curl', 'wget', 'powershell', 'pwsh']
    
    # 1. Get agent context
    inventory = SoftwareInventory.query.filter_by(hostname=hostname).all()
    sw_names = [s.software_name.lower() for s in inventory]
    
    asset = assets_collection.get(ids=[f"target_{hostname}"], include=["metadatas"])
    known_prereqs = asset['metadatas'][0].get('known_prereqs', '').lower().split(',') if asset and asset['metadatas'] else []

    # 2. Basic command start check
    cmd_clean = command.strip().lower()
    if cmd_clean:
        cmd_start = re.split(r'[^a-zA-Z0-9]', cmd_clean)[0]
        if cmd_start in common_engines:
            if cmd_start not in known_prereqs and not any(cmd_start in sw for sw in sw_names):
                return False, f"Missing execution engine: {cmd_start}"

    # 3. Explicit Atomic Dependency Check
    for dep in dependencies:
        desc = dep.get('description', '').lower()
        for engine in common_engines:
            if engine in desc:
                if engine not in known_prereqs and not any(engine in sw for sw in sw_names):
                    return False, f"Unmet Dependency: {dep.get('description').strip()}"
    
    return True, None

@app.route('/api/autopilot/stop', methods=['POST'])
@login_required
def stop_autopilot():
    global stop_full_cycle
    from tools.shared_state import stop_full_cycle as sfc
    import tools.shared_state
    tools.shared_state.stop_full_cycle = True
    return jsonify({"status": "success", "message": "Stop signal sent."})

@app.route('/api/autopilot/full-cycle', methods=['POST'])
@login_required
def run_full_cycle():
    """
    Full Intelligent Cycle driven by the Agentic AI Orchestrator.
    Streams NDJSON events while the AI manages CTI fetching, sequencing, and execution.
    """
    config = IntegrationsConfig.query.first()
    ollama_url = config.ollama_url if config and config.ollama_url else "http://localhost:11434"
    orchestrator = AIOrchestrator(ollama_url=ollama_url)

    @stream_with_context
    def ndjson_stream():
        try:
            for evt in orchestrator.orchestrate_full_cycle():
                # Inject timestamp for frontend
                evt['ts'] = datetime.now().strftime("%H:%M:%S")
                yield json.dumps(evt, ensure_ascii=False) + "\n"
        except Exception as e:
            import traceback
            print(traceback.format_exc())
            yield json.dumps({"event": "error", "message": str(e), "ts": datetime.now().strftime("%H:%M:%S")}) + "\n"

    return Response(
        ndjson_stream(),
        mimetype="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control": "no-cache",
        },
    )
@app.route('/api/manual', methods=['POST'])
@login_required
def run_manual_ttp():
    """
    AI-Orchestrated Manual Execution.
    """
    try:
        data = request.get_json()
        ttp_id = data.get('ttp_id', '').upper().strip()
        test_guid = data.get('test_guid')
        target_hostname = data.get('hostname')
        
        if not ttp_id and not test_guid:
            return jsonify({"status": "error", "output": "Please provide a valid TTP ID or Test GUID."})

        config = IntegrationsConfig.query.first()
        ollama_url = config.ollama_url if config and config.ollama_url else "http://localhost:11434"
        orchestrator = AIOrchestrator(ollama_url=ollama_url)

        # Delegate to orchestrator
        execution_result = orchestrator.orchestrate_manual_execution(target_hostname, ttp_id, test_guid=test_guid)
        
        return jsonify({
            "status": "executed", 
            "sec_status": execution_result.get('sec_status'), 
            "ttp_id": ttp_id, 
            "target": target_hostname, 
            "output": execution_result.get('output')
        })
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"status": "error", "output": str(e)}), 500

from xhtml2pdf import pisa
import io

def generate_report_pdf_bytes():
    from datetime import timedelta
    last_week = datetime.utcnow() - timedelta(days=7)
    results = SimulationResult.query.filter(SimulationResult.timestamp >= last_week).order_by(SimulationResult.timestamp.desc()).all()

    total_tests = len(results)
    alerted_count = sum(1 for r in results if r.status_detected)
    gap_count = total_tests - alerted_count
    prevented_count = sum(1 for r in results if 'prevented' in r.status.lower() or 'skipped' in r.status.lower())
    
    # Score is % of tests that were Alerted
    score = int((alerted_count / total_tests * 100)) if total_tests > 0 else 100

    # Get unique hosts
    host_count = len(set(r.target_hostname for r in results))

    # Get base URL for links
    request_port = request.host.split(':')[1] if ':' in request.host else '5000'
    base_url = f"http://{get_vmnet_ip()}:{request_port}"

    # Get latest threats for context
    with app.test_request_context():
        feed_data = get_cti_feed().get_json()

    # Enrich results with mitigations/detections for per-test display
    for r in results:
        r.mitigations = None
        r.detections = None
        stat_low = r.status.lower()
        if not r.status_detected: # This is a GAP
            mit_res = mitre_info.get(where={"id": r.ttp_id}, include=["documents"])
            if mit_res and mit_res['documents']:
                doc = mit_res['documents'][0]
                if "### MITIGATIONS ###" in doc:
                    r.mitigations = doc.split("### MITIGATIONS ###", 1)[1].split("###", 1)[0].strip()
                if "### DETECTIONS ###" in doc:
                    r.detections = doc.split("### DETECTIONS ###", 1)[1].split("###", 1)[0].strip()

    # --- Coverage Analytics for Charts (Last Week Only) ---
    coverage_stats = {
        "alerted": alerted_count,
        "gap": gap_count,
        "prevented": prevented_count
    }
    rendered = render_template('report.html',
                                date=datetime.now().strftime("%B %d, %Y"),
                                results=results,
                                total_tests=total_tests,
                                alerted_count=alerted_count,
                                gap_count=gap_count,
                                prevented_count=prevented_count,
                                score=score,
                                host_count=host_count,
                                base_url=base_url,
                                threats=feed_data[:3],
                                coverage=coverage_stats)

    pdf_out = io.BytesIO()
    pisa.CreatePDF(io.BytesIO(rendered.encode("UTF-8")), dest=pdf_out)
    pdf_out.seek(0)
    return pdf_out

def send_report_email(to_emails, pdf_bytes):
    config = SMTPConfig.query.first()
    if config:
        sender_email = config.username
        sender_password = config.password
        smtp_server = config.server
        smtp_port = config.port
    else:
        # Fallback
        sender_email = os.environ.get("SMTP_USERNAME", "beyondtheatomics@gmail.com")
        sender_password = os.environ.get("SMTP_PASSWORD", "dummy")
        smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
        smtp_port = int(os.environ.get("SMTP_PORT", 587))

    msg = MIMEMultipart()
    msg['Subject'] = "Beyond the Atomics - Weekly Security Exposure Report"
    msg['From'] = sender_email
    msg['To'] = ", ".join(to_emails)

    body = "Hello,\n\nPlease find attached the weekly security exposure report generated by Beyond the Atomics.\n\nBest Regards,\nBeyond the Atomics"
    msg.attach(MIMEText(body, 'plain'))
    pdf_attachment = MIMEApplication(pdf_bytes.read(), _subtype="pdf")
    pdf_attachment.add_header('Content-Disposition', 'attachment', filename=f"Security_Report_{datetime.now().strftime('%Y%m%d')}.pdf")
    msg.attach(pdf_attachment)
    pdf_bytes.seek(0)
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

@app.route('/api/smtp/config', methods=['GET', 'POST'])
@login_required
def smtp_config():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    config = SMTPConfig.query.first()
    
    if request.method == 'GET':
        if not config:
            return jsonify({"status": "success", "config": None})
        return jsonify({
            "status": "success", 
            "config": {
                "server": config.server,
                "port": config.port,
                "username": config.username,
                "is_enabled": config.is_enabled
            }
        })
        
    if request.method == 'POST':
        data = request.json
        if not config:
            config = SMTPConfig()
            db.session.add(config)
            
        config.server = data.get('server', 'smtp.gmail.com')
        config.port = int(data.get('port', 587))
        config.username = data.get('username')
        if data.get('password'):
            config.password = data.get('password')
        config.is_enabled = data.get('is_enabled', False)
        
        db.session.commit()
        return jsonify({"status": "success", "message": "SMTP Configuration saved."})

@app.route('/api/smtp/test', methods=['POST'])
@login_required
def test_smtp():
    if current_user.role != 'admin':
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
    data = request.json
    server_addr = data.get('server', 'smtp.gmail.com')
    port = int(data.get('port', 587))
    username = data.get('username')
    password = data.get('password')
    
    if not password:
        # Try to get existing password
        config = SMTPConfig.query.first()
        if config and config.password:
            password = config.password
        else:
            return jsonify({"status": "error", "message": "Password is required."})
            
    try:
        server = smtplib.SMTP(server_addr, port, timeout=10)
        server.starttls()
        server.login(username, password)
        server.quit()
        return jsonify({"status": "success", "message": "Connection successful!"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Connection failed: {str(e)}"})

@app.route('/report/download')
@login_required
def download_report():
    pdf_out = generate_report_pdf_bytes()
    return Response(pdf_out, mimetype='application/pdf', headers={"Content-disposition": f"attachment; filename=Security_Report_{datetime.now().strftime('%Y%m%d')}.pdf"})

@app.route('/api/report/email', methods=['POST'])
@login_required
def email_report():
    data = request.json
    user_ids = data.get('user_ids', [])
    if not user_ids:
        return jsonify({"status": "error", "message": "No users selected."}), 400
        
    emails = []
    for uid in user_ids:
        u = db.session.get(User, uid)
        if u and u.email:
            emails.append(u.email)
            
    if not emails:
        return jsonify({"status": "error", "message": "No valid email addresses found."}), 400
        
    pdf_out = generate_report_pdf_bytes()
    success = send_report_email(emails, pdf_out)
    
    if success:
        return jsonify({"status": "success", "message": f"Report emailed to {len(emails)} users."})
    else:
        return jsonify({"status": "error", "message": "Failed to send email. Check SMTP settings in .env."}), 500

@app.route('/report')
@login_required
def report_page():
    users = User.query.all()
    return render_template('report_viewer.html', users=users)

@app.route('/ttps')
@login_required
def ttps_page():
    # Use the new AtomicTest table to get TTP names and counts
    ttps = db.session.query(
        AtomicTest.ttp_id, 
        AtomicTest.ttp_name,
        db.func.count(AtomicTest.id).label('test_count')
    ).group_by(AtomicTest.ttp_id).all()
    
    # Also get MITRE metadata (descriptions) from ChromaDB
    mitre_data = mitre_info.get(include=["metadatas", "documents"])
    mitre_map = {mitre_data['ids'][i]: mitre_data['documents'][i].split('### MITIGATIONS ###')[0].replace('### DESCRIPTION ###', '').strip() 
                 for i in range(len(mitre_data.get('ids', [])))}

    # Get test metadata for search blob
    all_tests = AtomicTest.query.all()
    test_meta = {}
    for t in all_tests:
        if t.ttp_id not in test_meta:
            test_meta[t.ttp_id] = []
        test_meta[t.ttp_id].append(f"{t.test_name} {t.description} {t.command}")

    merged = []
    for t in ttps:
        # Get platforms for this TTP (all platforms from its tests)
        all_platforms = set()
        ttp_tests = [x for x in all_tests if x.ttp_id == t.ttp_id]
        for test in ttp_tests:
            if test.platforms:
                for p in test.platforms.split(','):
                    all_platforms.add(p.strip().lower())
                    
        search_blob = (" ".join(test_meta.get(t.ttp_id, []))).lower()
        search_blob = search_blob.replace('"', '').replace("'", "") # Clean quotes

        merged.append({
            "id": t.ttp_id,
            "name": t.ttp_name,
            "description": mitre_map.get(t.ttp_id, "No description available."),
            "platforms": list(all_platforms),
            "runnable": True,
            "test_count": t.test_count,
            "search_blob": search_blob
        })
    return render_template('ttps.html', ttps=merged)

@app.route('/api/ttps/<ttp_id>/tests')
@login_required
def get_ttp_tests(ttp_id):
    tests = AtomicTest.query.filter_by(ttp_id=ttp_id).all()
    return jsonify([{
        "guid": t.test_guid,
        "name": t.test_name,
        "description": t.description,
        "platforms": t.platforms.split(',') if t.platforms else [],
        "executor": t.executor,
        "command": t.command,
        "cleanup_command": t.cleanup_command,
        "dependencies": json.loads(t.dependencies) if t.dependencies else [],
        "safety_rating": t.safety_rating,
        "safety_reason": t.safety_reason,
        "elevation_required": t.elevation_required,
        "user_context": t.user_context,
        "required_software": t.required_software.split(',') if t.required_software else [],
        "target_apps": t.target_apps.split(',') if t.target_apps else []
    } for t in tests])

@app.route('/apts', methods=['GET', 'POST'])
@login_required
def apts_page():
    if request.method == 'POST':
        # Create custom group
        name = request.form.get('name')
        description = request.form.get('description')
        selected_ttps = request.form.getlist('ttps')
        
        import uuid
        apt_id = f"custom_{uuid.uuid4().hex[:8]}"
        new_group = APTGroup(
            id=apt_id,
            name=name,
            aliases="",
            description=description
        )
        db.session.add(new_group)
        for ttp in selected_ttps:
            new_ttp = APTTTP(apt_id=apt_id, ttp_id=ttp)
            db.session.add(new_ttp)
        db.session.commit()
        flash(f"Custom group '{name}' created successfully.", "success")
        return redirect(url_for('apts_page'))

    groups_data = APTGroup.query.all()
    groups = []
    
    # To display TTP names along with IDs
    mitre_data = mitre_info.get(include=["metadatas"])
    mitre_map = {}
    if mitre_data and mitre_data.get('ids'):
        for i in range(len(mitre_data['ids'])):
            mitre_map[mitre_data['ids'][i]] = mitre_data['metadatas'][i].get('name', mitre_data['ids'][i])
            
    for g in groups_data:
        ttps = APTTTP.query.filter_by(apt_id=g.id).all()
        ttp_list = [{"id": t.ttp_id, "name": mitre_map.get(t.ttp_id, t.ttp_id)} for t in ttps]
        
        # Parse links in description
        desc = g.description
        desc = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', desc)
        
        groups.append({
            "id": g.id,
            "name": g.name,
            "aliases": g.aliases.split(', ') if g.aliases else [],
            "description": desc,
            "ttps": ttp_list
        })
    
    # Sort alphabetically by name
    groups = sorted(groups, key=lambda x: x['name'])
    
    # Also pass all TTPs for the "Create Group" dropdown
    all_ttps = [{"id": mitre_data['ids'][i], "name": mitre_data['metadatas'][i].get('name')} for i in range(len(mitre_data.get('ids', [])))]
    all_ttps = sorted(all_ttps, key=lambda x: x['id'])
    
    return render_template('apts.html', groups=groups, all_ttps=all_ttps)

@app.route('/api/schedule/automate', methods=['POST'])
@login_required
def automate_scheduling():
    from datetime import timedelta
    try:
        # 1. Sync threats first
        smart_fetch_and_store()
        
        # 2. Get active agents
        targets = get_active_targets()
        if not targets:
            return jsonify({"status": "error", "message": "No active agents found to schedule."})
        
        # 3. Plan for the next 7 days
        start_date = datetime.now()
        schedules_created = 0
        
        for i in range(7):
            current_day = start_date + timedelta(days=i)
            day_str = current_day.strftime("%Y-%m-%d")
            
            # Select 1 agent per day (cycle through them)
            target = targets[i % len(targets)]
            hostname = target['hostname']
            target_os = target['os']
            candidate_ttps = target['ttps'][:10] # Max 10 TTPs per day
            
            base_time = datetime.strptime("12:00", "%H:%M")
            
            for j, ttp_id in enumerate(candidate_ttps):
                # Space by 5 minutes
                run_time = (base_time + timedelta(minutes=j*5)).strftime("%H:%M")
                
                # Check if already scheduled
                exists = Schedule.query.filter_by(
                    target_hostname=hostname,
                    ttp_id=ttp_id,
                    run_date=day_str,
                    run_time=run_time
                ).first()
                
                if not exists:
                    new_sch = Schedule(
                        task_type='emulation',
                        target_hostname=hostname,
                        ttp_id=ttp_id,
                        run_date=day_str,
                        run_time=run_time
                    )
                    db.session.add(new_sch)
                    schedules_created += 1
        
        db.session.commit()
        return jsonify({"status": "success", "count": schedules_created})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/simulation/delete/<int:sim_id>', methods=['POST'])
@login_required
def delete_simulation(sim_id):
    """Deletes a specific simulation result from the database."""
    try:
        sim = SimulationResult.query.get(sim_id)
        if sim:
            db.session.delete(sim)
            db.session.commit()
            return jsonify({"status": "success", "message": "Log deleted successfully."})
        return jsonify({"status": "error", "message": "Simulation not found."}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/schedule/auto-fill-toggle', methods=['POST'])
@login_required
def toggle_auto_fill():
    """Toggles the 'Automate full week when empty' switch."""
    try:
        data = request.get_json()
        enabled = data.get('enabled', False)
        config = IntegrationsConfig.query.first()
        if not config:
            config = IntegrationsConfig()
            db.session.add(config)
        config.auto_fill_week = enabled
        db.session.commit()
        return jsonify({"status": "success", "auto_fill_week": config.auto_fill_week})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/scheduling', methods=['GET', 'POST'])
@login_required
def scheduling():
    if request.method == 'POST':
        task_type = request.form.get('task_type', 'emulation') # Default to emulation
        target_hostname = request.form.get('target_hostname')
        ttp_id = request.form.get('ttp_id', '').upper()
        test_guid = request.form.get('test_guid') # Support test_guid
        run_date = request.form.get('run_date')
        run_time = request.form.get('run_time')
        
        new_schedule = Schedule(
            task_type=task_type,
            target_hostname=target_hostname,
            ttp_id=ttp_id,
            test_guid=test_guid,
            run_date=run_date,
            run_time=run_time
        )
        db.session.add(new_schedule)
        db.session.commit()
        flash('Schedule added successfully.', 'success')
        return redirect(url_for('scheduling'))

    schedules = Schedule.query.order_by(Schedule.run_date.asc(), Schedule.run_time.asc()).all()
    assets = assets_collection.get(include=["metadatas"])
    hostnames = [meta.get('hostname') for meta in assets.get('metadatas', [])]
    
    # Fetch auto-fill status
    config = IntegrationsConfig.query.first()
    auto_fill_week = config.auto_fill_week if config else False

    return render_template('scheduling.html', schedules=schedules, hostnames=hostnames, auto_fill_week=auto_fill_week)

@app.route('/api/schedule/upcoming')
@login_required
def upcoming_schedules():
    from datetime import datetime
    now_date = datetime.now().strftime("%Y-%m-%d")

    # Get next 5 tasks: either for today/future, or past tasks that haven't run yet
    schedules = Schedule.query.filter(
        (Schedule.enabled == True) & 
        ((Schedule.run_date >= now_date) | (Schedule.last_run == None))
    ).order_by(Schedule.run_date.asc(), Schedule.run_time.asc()).limit(5).all()

    out = []
    for s in schedules:
        out.append({
            "target": s.target_hostname or "All",
            "ttp": s.ttp_id or "Sync",
            "date": s.run_date,
            "time": s.run_time,
            "type": s.task_type
        })
    return jsonify(out)
@app.route('/api/schedule/bulk', methods=['POST'])
@login_required
def bulk_schedule():
    try:
        data = request.json
        hostname = data.get('hostname')
        ttps = data.get('ttps', [])
        date = data.get('date')
        start_time = data.get('start_time') # HH:MM
        
        if not hostname or not ttps or not date or not start_time:
            return jsonify({"status": "error", "message": "Missing required fields."})
            
        base_time = datetime.strptime(start_time, "%H:%M")
        created_count = 0
        
        for i, ttp_id in enumerate(ttps):
            # Space by 5 minutes
            run_time = (base_time + timedelta(minutes=i*5)).strftime("%H:%M")
            
            new_sch = Schedule(
                task_type='emulation',
                target_hostname=hostname,
                ttp_id=ttp_id,
                run_date=date,
                run_time=run_time
            )
            db.session.add(new_sch)
            created_count += 1
            
        db.session.commit()
        return jsonify({"status": "success", "count": created_count})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/api/schedule/delete/<int:schedule_id>', methods=['POST'])
@login_required
def delete_schedule(schedule_id):
    sch = Schedule.query.get_or_404(schedule_id)
    db.session.delete(sch)
    db.session.commit()
    return jsonify({"status": "success"})

@app.route('/api/schedule/delete-all', methods=['POST'])
@login_required
def delete_all_schedules():
    """Deletes all active schedules from the database."""
    try:
        Schedule.query.delete()
        db.session.commit()
        return jsonify({"status": "success", "message": "All schedules cleared."})
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": str(e)}), 500

def scheduled_task_executor():
    with app.app_context():
        # Check if we need to auto-fill the week
        config = IntegrationsConfig.query.first()
        if config and config.auto_fill_week:
            # If no active/enabled schedules exist, auto-fill
            active_count = Schedule.query.filter_by(enabled=True).count()
            if active_count == 0:
                print("[*] Auto-fill week is ON and schedule is empty. Automating...")
                # Call the internal logic of automate_scheduling
                from datetime import timedelta
                try:
                    smart_fetch_and_store()
                    targets = get_active_targets()
                    if targets:
                        start_date = datetime.now()
                        for i in range(7):
                            current_day = start_date + timedelta(days=i)
                            day_str = current_day.strftime("%Y-%m-%d")
                            for target in targets:
                                cand_ttps = target.get('ttps', [])
                                if not cand_ttps: continue
                                ttp = cand_ttps[i % len(cand_ttps)]
                                base_time = f"{10 + (i % 8):02d}:00"
                                new_sch = Schedule(
                                    task_type='emulation',
                                    target_hostname=target['hostname'],
                                    ttp_id=ttp,
                                    run_date=day_str,
                                    run_time=base_time
                                )
                                db.session.add(new_sch)
                        db.session.commit()
                        print(f"[+] Auto-fill complete.")
                except Exception as e:
                    print(f"[!] Auto-fill error: {e}")

        now = datetime.now()
        now_date = now.strftime("%Y-%m-%d")
        now_time = now.strftime("%H:%M")
        
        # Check for matches on both date and time
        active_schedules = Schedule.query.filter_by(
            run_date=now_date, 
            run_time=now_time, 
            enabled=True
        ).all()
        
        # Also check for schedules that have no date (legacy/manual legacy) matching current time
        legacy_schedules = Schedule.query.filter(
            Schedule.run_date == None,
            Schedule.run_time == now_time,
            Schedule.enabled == True
        ).all()
        
        for sch in active_schedules + legacy_schedules:
            print(f"[*] Running scheduled task: {sch.task_type}")
            if sch.task_type == 'fetch':
                smart_fetch_and_store()
            elif sch.task_type == 'emulation':
                # Run a simple autopilot cycle for this specific hostname and TTP
                asset = assets_collection.get(ids=[f"target_{sch.target_hostname}"], include=["metadatas"])
                if asset and asset['metadatas']:
                    target_os = asset['metadatas'][0].get('os', 'windows').lower()
                    agent_is_privileged = asset['metadatas'][0].get('is_privileged', False)
                    
                    payload_cmd = ""
                    cleanup_cmd = None
                    ttp_name = sch.ttp_id
                    dependencies = []
                    elevation_required = False

                    # 1. Try to fetch from local database if GUID is provided
                    if sch.test_guid:
                        test_rec = AtomicTest.query.filter_by(test_guid=sch.test_guid).first()
                        if test_rec:
                            # Check compatibility
                            platforms = [p.strip().lower() for p in test_rec.platforms.split(',')] if test_rec.platforms else []
                            if target_os in platforms or 'all' in platforms:
                                payload_cmd = test_rec.command
                                cleanup_cmd = test_rec.cleanup_command
                                ttp_name = test_rec.test_name
                                dependencies = json.loads(test_rec.dependencies) if test_rec.dependencies else []
                                elevation_required = test_rec.elevation_required
                            else:
                                print(f"[*] Scheduled GUID {sch.test_guid} is not compatible with {target_os}. Falling back.")

                    # 2. Fallback: Fetch first compatible test if no GUID or GUID mismatch
                    if not payload_cmd:
                        test_rec = AtomicTest.query.filter(
                            AtomicTest.ttp_id == sch.ttp_id,
                            (AtomicTest.platforms.like(f"%{target_os}%")) | (AtomicTest.platforms.like("%all%"))
                        ).first()
                        
                        if test_rec:
                            payload_cmd = test_rec.command
                            cleanup_cmd = test_rec.cleanup_command
                            ttp_name = test_rec.test_name
                            dependencies = json.loads(test_rec.dependencies) if test_rec.dependencies else []
                            elevation_required = test_rec.elevation_required
                        else:
                            # Fallback to GitHub fetcher
                            raw_data = fetch_atomic_test(sch.ttp_id, target_os)
                            if raw_data and "test" in raw_data:
                                payload_cmd = raw_data["test"]["executor"].get("command", "")
                                cleanup_cmd = raw_data["test"]["executor"].get("cleanup_command", None)
                                ttp_name = raw_data["test"].get("name", sch.ttp_id)
                                dependencies = raw_data.get("dependencies", [])
                                elevation_required = raw_data['test'].get('executor', {}).get('elevation_required', False)

                    if payload_cmd:
                        siem_config = get_siem_config_dict()
                        target_context = build_target_context(sch.target_hostname)

                        execution_result = run_remote_emulation(
                            command=payload_cmd,
                            target_hostname=sch.target_hostname,
                            cleanup_command=cleanup_cmd,
                            ttp_id=sch.ttp_id,
                            target_os=target_os,
                            dependencies=dependencies,
                            siem_config=siem_config,
                            target_context=target_context,
                            elevation_required=elevation_required,
                            agent_is_privileged=agent_is_privileged,
                            test_name=ttp_name
                        )
                        
                        # Save result
                        new_record = SimulationResult(
                            ttp_id=sch.ttp_id,
                            ttp_name=ttp_name,
                            test_name=execution_result.get('test_name'),
                            target_hostname=sch.target_hostname,
                            status=execution_result.get('sec_status'),
                            output=execution_result.get('output'),
                            stderr=execution_result.get('stderr'),
                            exit_code=execution_result.get('exit_code'),
                            start_time=execution_result.get('start_time'),
                            end_time=execution_result.get('end_time'),
                            status_run=execution_result.get('status_run'),
                            status_detected=execution_result.get('status_detected'),
                            execution_type='Scheduled',
                            reasoning="Scheduled execution",
                            wazuh_severity=execution_result.get('wazuh_severity'),
                            wazuh_rule_desc=execution_result.get('wazuh_rule_desc'),
                            ai_reasoning=execution_result.get('ai_reasoning'),
                            remediation_advice=execution_result.get('remediation')
                        )
                        db.session.add(new_record)
                    else:
                        print(f"[!] No compatible payload found for scheduled TTP {sch.ttp_id} on {sch.target_hostname}")
            sch.last_run = datetime.utcnow()
            db.session.commit()

def send_weekly_reports_job():
    with app.app_context():
        config = SMTPConfig.query.first()
        if not config or not config.is_enabled:
            print("[-] Weekly reports are disabled in SMTP configuration. Skipping.")
            return

        print("[*] Running automated weekly report email job...")
        users = User.query.all()
        emails = [u.email for u in users if u.email]
        if not emails:
            print("[-] No users found to send weekly report.")
            return
            
        pdf_bytes = generate_report_pdf_bytes()
        success = send_report_email(emails, pdf_bytes)
        if success:
            print(f"[+] Weekly reports emailed successfully to {len(emails)} users.")

scheduler = BackgroundScheduler()
scheduler.add_job(func=scheduled_task_executor, trigger="interval", minutes=1)
scheduler.add_job(func=send_weekly_reports_job, trigger="cron", day_of_week='thu', hour=13, minute=0)
scheduler.start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)
