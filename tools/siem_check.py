import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
import sys
import argparse
from datetime import datetime, timedelta

# Suppress insecure request warnings for self-signed certificates (Wazuh default)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

"""
SIEM Check Agent (Wazuh - Indexer Only)
This script verifies TTP execution by querying the Wazuh Indexer (OpenSearch) 
directly on port 9200.

How it works:
1. Authentication: Uses standard Basic Auth (User/Password) against the Indexer.
2. Targeted Alert Query: Searches the 'wazuh-alerts-*' index for specific:
   - agent_id: The monitored endpoint ID.
   - timestamp range: The exact window of the emulation.
   - query_string: The TTP ID (e.g., T1003.001) or base technique.
3. Decision: If 'hits' > 0, the SIEM has evidence of the technique.
"""

def check_indexer(ttp_id, agent_id, start_time, end_time, wazuh_ip, user, password, command=None):
    """
    Primary check: Queries the Wazuh Indexer (OpenSearch) on port 9200.
    Implements a tiered search strategy.
    """
    indexer_url = f"https://{wazuh_ip}:9200/wazuh-alerts-*/_search"
    
    # 1. Extract and sort keywords
    tokens = []
    if command:
        import re
        # Split by spaces and filter out single-character tokens or symbols
        raw_tokens = re.split(r'\s+', command)
        for t in raw_tokens:
            t = t.strip().strip('"').strip("'")
            if len(t) > 1:
                tokens.append(t)
    
    # Sort tokens by length descending
    tokens.sort(key=len, reverse=True)

    # 2. Build tiered queries
    queries_to_run = []
    
    # Tier 1: TTP_ID OR Longest Keyword
    tier1_parts = [f"\"{ttp_id}\""]
    if tokens:
        longest = tokens.pop(0)
        tier1_parts.append(f"\"{longest}\"")
    queries_to_run.append(" OR ".join(tier1_parts))

    # Subsequent Tiers: Pairs of remaining keywords
    while tokens:
        pair = []
        pair.append(f"\"{tokens.pop(0)}\"")
        if tokens:
            pair.append(f"\"{tokens.pop(0)}\"")
        queries_to_run.append(" OR ".join(pair))

    print(f"\n[SIEM_CHECK] [DEBUG] Tiered Search for {ttp_id} on Agent {agent_id}")
    print(f"[SIEM_CHECK] [DEBUG] Command: {command}")

    # 3. Execute queries sequentially
    for idx, final_query in enumerate(queries_to_run):
        print(f"[SIEM_CHECK] [DEBUG] Attempt {idx + 1}: {final_query}")
        
        query_body = {
            "size": 10,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"match": {"agent.id": agent_id}},
                        {"query_string": {"query": final_query}},
                        {"range": {
                            "timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }}
                    ]
                }
            }
        }

        try:
            response = requests.post(
                indexer_url, 
                auth=HTTPBasicAuth(user, password), 
                json=query_body, 
                verify=False, 
                timeout=15
            )
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', {}).get('total', {}).get('value', 0)
                
                if hits > 0:
                    print(f"[SIEM_CHECK] [DEBUG] Match found in Attempt {idx + 1}! Hits: {hits}")
                    raw_hits = data.get('hits', {}).get('hits', [])
                    
                    max_level = 0
                    rule_desc = "No description found"
                    
                    for hit in raw_hits:
                        source = hit.get('_source', {})
                        level = int(source.get('rule', {}).get('level', 0))
                        if level > max_level:
                            max_level = level
                            rule_desc = source.get('rule', {}).get('description', rule_desc)

                    return {
                        "status": "success",
                        "alerted": True,
                        "count": hits,
                        "wazuh_severity": str(max_level),
                        "wazuh_rule_desc": rule_desc,
                        "data": [hit['_source'] for hit in raw_hits]
                    }
                else:
                    print(f"[SIEM_CHECK] [DEBUG] No hits for Attempt {idx + 1}")
            else:
                print(f"[SIEM_CHECK] [DEBUG] Error in Attempt {idx + 1}: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"[SIEM_CHECK] [DEBUG] Exception in Attempt {idx + 1}: {e}")

    # 4. Final result if no alerts found in any tier
    print(f"[SIEM_CHECK] [DEBUG] All search tiers exhausted. No alerts found.")
    return {"status": "success", "alerted": False, "count": 0}

def check_alerts(ttp_id, agent_id, start_time, end_time, wazuh_ip, user, password, command=None):
    """
    Unified check function.
    Focuses exclusively on the Indexer (9200) as it's the most reliable for alert searching.
    """
    print(f"\n[SIEM_CHECK] Starting check for {ttp_id} on Agent {agent_id}")
    return check_indexer(ttp_id, agent_id, start_time, end_time, wazuh_ip, user, password, command=command)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Standalone SIEM Check Agent for Wazuh")
    parser.add_argument("--ttp", required=True, help="TTP ID to search for (e.g. T1003.001)")
    parser.add_argument("--agent", required=True, help="Wazuh Agent ID (e.g. 001)")
    parser.add_argument("--start", required=True, help="Start time in ISO format")
    parser.add_argument("--end", required=True, help="End time in ISO format")
    parser.add_argument("--ip", required=True, help="Wazuh Manager IP")
    parser.add_argument("--user", required=True, help="Wazuh API User")
    parser.add_argument("--pwd", required=True, help="Wazuh API Password")

    args = parser.parse_args()

    result = check_alerts(args.ttp, args.agent, args.start, args.end, args.ip, args.user, args.pwd)
    print(json.dumps(result, indent=2))