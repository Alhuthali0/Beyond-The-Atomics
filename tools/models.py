from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy_utils import StringEncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine
import os
from datetime import datetime

db = SQLAlchemy()

db_encryption_key = os.environ.get("DB_ENCRYPTION_KEY", "default-secret-key-must-be-32-bytes!")

class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_type = db.Column(db.String(50), nullable=False) # 'fetch' or 'emulation' 
    target_hostname = db.Column(db.String(100))
    ttp_id = db.Column(db.String(50))
    test_guid = db.Column(db.String(100))
    run_date = db.Column(db.String(10)) # YYYY-MM-DD
    run_time = db.Column(db.String(10), nullable=False) # HH:MM
    last_run = db.Column(db.DateTime)
    enabled = db.Column(db.Boolean, default=True)

class SimulationResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    start_time = db.Column(db.String(50)) # ISO 8601 UTC
    end_time = db.Column(db.String(50))   # ISO 8601 UTC
    ttp_id = db.Column(db.String(50))
    ttp_name = db.Column(db.String(200))
    target_hostname = db.Column(db.String(100))
    status = db.Column(db.String(100)) # E.g., Execution: Success | Detection: GAP
    output = db.Column(StringEncryptedType(db.Text, db_encryption_key, AesEngine, 'pkcs5'))
    stderr = db.Column(db.Text)
    exit_code = db.Column(db.Integer)
    status_run = db.Column(db.Boolean, default=False)
    status_detected = db.Column(db.Boolean, default=False)
    execution_type = db.Column(db.String(50)) 
    reasoning = db.Column(db.Text)
    ai_reasoning = db.Column(db.Text)
    
    # New DFIR reasoning fields
    calculated_score = db.Column(db.Integer)
    calculation_reasoning = db.Column(db.Text)
    execution_status = db.Column(db.Text)
    dfir_verdict = db.Column(db.Text)

    test_name = db.Column(db.String(255))
    wazuh_severity = db.Column(db.String(20))
    wazuh_rule_desc = db.Column(db.Text)
    remediation_advice = db.Column(db.Text)
    cti_context = db.Column(db.Text)

    # Enriched metadata for correlation
    wazuh_agent_id = db.Column(db.String(50))
    executed_command = db.Column(db.Text)
    spawned_processes = db.Column(db.Text) # JSON string or comma-separated
    created_files = db.Column(db.Text)     # JSON string or comma-separated
    parent_process = db.Column(db.Text)    # JSON string or comma-separated

class TTPMitigation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ttp_id = db.Column(db.String(50), nullable=False)
    mitigation_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)

class APTGroup(db.Model):
    id = db.Column(db.String(50), primary_key=True) # E.g., 'G0016'
    name = db.Column(db.String(255), nullable=False)
    aliases = db.Column(db.String(500))
    description = db.Column(db.Text)

class APTTTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    apt_id = db.Column(db.String(50), db.ForeignKey('apt_group.id'), nullable=False)
    ttp_id = db.Column(db.String(50), nullable=False)

class SoftwareInventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    software_name = db.Column(db.String(255), nullable=False)
    version = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AtomicTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ttp_id = db.Column(db.String(50), nullable=False)
    ttp_name = db.Column(db.String(255))
    test_guid = db.Column(db.String(100), unique=True, nullable=False)
    test_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    platforms = db.Column(db.String(255)) # Comma separated
    executor = db.Column(db.String(50))
    command = db.Column(db.Text)
    cleanup_command = db.Column(db.Text)
    dependencies = db.Column(db.Text) # JSON string of dependencies
    safety_rating = db.Column(db.String(20)) # 'safe' or 'destructive'
    safety_reason = db.Column(db.Text)
    elevation_required = db.Column(db.Boolean, default=False)
    user_context = db.Column(db.String(50))
    required_software = db.Column(db.String(255)) # Comma separated
    target_apps = db.Column(db.String(255)) # Comma separated

class AgentSysInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False, unique=True)
    os_version = db.Column(db.String(200))
    cpu = db.Column(db.String(200))
    ram = db.Column(db.String(100))
    storage = db.Column(db.String(200))

class AgentPort(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    port = db.Column(db.String(20))
    protocol = db.Column(db.String(10))
    service_name = db.Column(db.String(100))
    
class IntegrationsConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # SIEM (Wazuh)
    wazuh_enabled = db.Column(db.Boolean, default=False)
    wazuh_ip = db.Column(db.String(255), default="192.168.1.235")
    wazuh_user = db.Column(db.String(255), default="admin")
    wazuh_password = db.Column(db.String(255), default="admin")
    
    # CTI (AlienVault OTX)
    otx_api_key = db.Column(db.String(255), default="")
    
    # AI (Ollama)
    ollama_enabled = db.Column(db.Boolean, default=False)
    ollama_url = db.Column(db.String(255), default="http://localhost:11434")
    ollama_model = db.Column(db.String(255), default="phi3")

    # Automation
    auto_fill_week = db.Column(db.Boolean, default=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(StringEncryptedType(db.String(150), db_encryption_key, AesEngine, 'pkcs5'), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='Analyst')
    status = db.Column(db.String(20), nullable=False, default='pending') # 'pending' or 'approved'

class SMTPConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    server = db.Column(db.String(255), nullable=False, default='smtp.gmail.com')
    port = db.Column(db.Integer, nullable=False, default=587)
    username = db.Column(StringEncryptedType(db.String(255), db_encryption_key, AesEngine, 'pkcs5'), nullable=False)
    password = db.Column(StringEncryptedType(db.String(255), db_encryption_key, AesEngine, 'pkcs5'), nullable=False)
    is_enabled = db.Column(db.Boolean, default=False)
