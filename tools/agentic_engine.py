import requests
import json

def analyze_test_result(ttp_id, command, target_os, exit_code, stdout, stderr, wazuh_severity, wazuh_rule_desc, asset_classification="Internal Server", test_name=None, ollama_url="http://localhost:11434", target_hostname="unknown"):
    """
    Uses Ollama Phi3 to provide a contextual DFIR verdict and risk assessment using the DREAD model.
    DREAD = (Damage + Reproducibility + Exploitability + Affected Users + Discoverability) / 5
    """
    from tools.db import execution_history
    
    current_test = test_name or ttp_id
    
    # Map classification to numeric value for instructions
    crit_map = {
        "User Workstation": 0,
        "Internal Server": 2,
        "Public Facing Server": 4
    }
    criticality_value = crit_map.get(asset_classification, 2)
    
    # Handle Wazuh severity
    try:
        base_score = int(wazuh_severity)
    except:
        base_score = 0

    # 1. RETRIEVAL
    query_text = f"What was the execution result of {ttp_id} on {target_hostname}?"
    rag_context = "No historical context found in the database."
    try:
        results = execution_history.query(query_texts=[query_text], n_results=1)
        if results["documents"] and results["documents"][0]:
            rag_context = results["documents"][0][0]
    except Exception as e:
        rag_context = f"Failed to retrieve context: {e}"

    # Truncate outputs to prevent context window overflow
    safe_stdout = str(stdout)[:800] if stdout else "None"
    safe_stderr = str(stderr)[:500] if stderr else "None"

    # 2. AUGMENTATION: Inject the retrieved context AND actual telemetry into the prompt
    prompt = f"""
    You are a Senior DFIR Analyst. Analyze the following threat emulation results and provide a structured technical verdict using the DREAD risk model.
    Do not invent commands. Only analyze the exact command provided below.

    ### EXECUTION TELEMETRY ###
    * Command Executed: {command}
    * Exit Code: {exit_code} (Code 0 means success)
    * STDOUT: {safe_stdout}
    * STDERR: {safe_stderr}
    
    ### ENVIRONMENTAL CONTEXT ###
    * Target OS: {target_os}
    * Asset Classification: {asset_classification}
    * Base Wazuh Alert Level: {base_score}
    * Wazuh Rule Description: {wazuh_rule_desc}
    * Historical Context: {rag_context}

    ### DREAD RISK ASSESSMENT TASK ###
    Assign a strict integer score from 1 to 10 for each category. Do not use percentages.
    1. **Damage**: 1 is no damage, 10 is total system destruction.
    2. **Reproducibility**: 1 is highly complex, 10 is trivial to repeat.
    3. **Exploitability**: 1 requires advanced tools, 10 requires basic commands.
    4. **Affected Users**: 1 impacts a single user, 10 impacts the entire domain.
    5. **Discoverability**: 1 is impossible to find, 10 is public knowledge.

### TASK ###
    Provide your analysis as bullet points addressing:
    * **Attack Success:** Analyze the STDOUT and STDERR. Did the underlying command achieve its goal, or did it fail due to missing permissions (e.g., sudo password prompt)? DO NOT rely solely on the Exit Code if STDOUT indicates a permission block.
    * **Alert Accuracy:** Is the Wazuh rule description appropriate for the command executed?
    * **Severity Appropriateness:** Is the alert level acceptable based on the asset classification?
    * **Technical Outcome:** Concise summary of what the STDOUT reveals about the target. If the output shows a password prompt or permission denied, state explicitly that the attack was blocked.

    ### OUTPUT FORMAT (STRICT JSON) ###
    {{
      "dread": {{
        "damage": <int 1-10>,
        "reproducibility": <int 1-10>,
        "exploitability": <int 1-10>,
        "affected_users": <int 1-10>,
        "discoverability": <int 1-10>
      }},
      "execution_status": "Short summary of process result",
      "dfir_verdict": "Markdown bullet points following the task instructions. Do not use percentages."
    }}
    """
    
    try:
        payload = {
            "model": "phi3",
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "num_predict": 600,
                "temperature": 0.0 # Set to absolute 0 to stop hallucination
            }
        }
        response = requests.post(f"{ollama_url}/api/generate", json=payload, timeout=150)
        if response.status_code == 200:
            ai_raw = response.json().get('response', '{}').strip()
            ai_data = json.loads(ai_raw)
            
            # Recalculate average programmatically to prevent LLM math errors
            d = ai_data.get('dread', {})
            scores = [d.get('damage', 0), d.get('reproducibility', 0), d.get('exploitability', 0), d.get('affected_users', 0), d.get('discoverability', 0)]
            ai_data['calculated_score'] = sum(scores) / 5
            
            # Build the DREAD Breakdown string
            dread_md = "### DREAD Breakdown\n"
            dread_md += f"* **Damage:** {d.get('damage', 0)}/10\n"
            dread_md += f"* **Reproducibility:** {d.get('reproducibility', 0)}/10\n"
            dread_md += f"* **Exploitability:** {d.get('exploitability', 0)}/10\n"
            dread_md += f"* **Affected Users:** {d.get('affected_users', 0)}/10\n"
            dread_md += f"* **Discoverability:** {d.get('discoverability', 0)}/10\n\n"
            dread_md += "### Analysis Verdict\n"
            
            ai_data['calculation_reasoning'] = f"Average of ({'+'.join(map(str, scores))}) / 5"
            ai_data['dfir_verdict'] = dread_md + ai_data.get('dfir_verdict', '')
            return ai_data
        else:
            raise Exception(f"Ollama error: {response.status_code}")
    except Exception as e:
        total = (base_score + criticality_value) / 2
        return {
            "calculated_score": total,
            "calculation_reasoning": "AI Analysis Unavailable. Manual fallback calculation.",
            "execution_status": "Executed (AI Analysis Unavailable)",
            "dfir_verdict": f"**Status:** Analysis failed due to error: {e}\n**Fallback Risk Score:** {total}"
        }