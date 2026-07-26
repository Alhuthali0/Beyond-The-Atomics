import csv
import json
import os
import re
import time
from typing import Dict, List, Tuple

import requests
from bs4 import BeautifulSoup

from db import mitre_info

DETECTION_ID_PATTERN = re.compile(r"\b(?:DET|AN)\d{4}\b")
CSV_PATH = "mitre_complete_info.csv"
BASE_DETECTION_URL = "https://attack.mitre.org/detectionstrategies/{det_id}/"
BASE_TECHNIQUE_URL = "https://attack.mitre.org/techniques/{ttp_id}/"

def _debug_log(hypothesis_id: str, location: str, message: str, data=None, run_id: str = "initial"):
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
        with open("debug-f7f4dc.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass

def table_to_markdown(table) -> str:
    rows = table.find_all("tr")
    if not rows:
        return ""

    parsed_rows: List[List[str]] = []
    for row in rows:
        cols = row.find_all(["th", "td"])
        values = [c.get_text(" ", strip=True) for c in cols]
        if values:
            parsed_rows.append(values)

    if not parsed_rows:
        return ""

    headers = parsed_rows[0]
    header_line = "| " + " | ".join(headers) + " |"
    sep_line = "| " + " | ".join(["---"] * len(headers)) + " |"
    body_lines = [
        "| " + " | ".join(row + [""] * (len(headers) - len(row))) + " |"
        for row in parsed_rows[1:]
    ]
    return "\n".join([header_line, sep_line, *body_lines]).strip()

def scrape_detection_strategy(det_id: str, session: requests.Session) -> str:
    url = BASE_DETECTION_URL.format(det_id=det_id)
    try:
        response = session.get(url, timeout=12)
        if response.status_code != 200:
            return ""
    except requests.RequestException:
        return ""

    soup = BeautifulSoup(response.text, "html.parser")

    log_sources_table = None
    mutable_elements_table = None

    for heading in soup.find_all(["h2", "h3", "h4", "h5", "h6"]):
        heading_text = heading.get_text(" ", strip=True).lower()
        if "log sources" in heading_text:
            log_sources_table = heading.find_next("table")
        elif "mutable elements" in heading_text:
            mutable_elements_table = heading.find_next("table")

    if not log_sources_table or not mutable_elements_table:
        all_tables = soup.find_all("table")
        if not log_sources_table and all_tables:
            log_sources_table = all_tables[0]
        if not mutable_elements_table and len(all_tables) > 1:
            mutable_elements_table = all_tables[1]

    sections: List[str] = [f"#### {det_id}"]

    if log_sources_table:
        sections.append("##### Log Sources")
        sections.append(table_to_markdown(log_sources_table))

    if mutable_elements_table:
        sections.append("##### Mutable Elements")
        sections.append(table_to_markdown(mutable_elements_table))

    if len(sections) == 1:
        return ""

    return "\n".join(s for s in sections if s).strip() + "\n"

def parse_detection_ids(detection_text: str) -> List[str]:
    if not detection_text:
        return []
    return sorted(set(DETECTION_ID_PATTERN.findall(detection_text)))

def scrape_technique_detection(ttp_id: str, session: requests.Session) -> str:
    # Handle sub-techniques (e.g., T1055.011 -> T1055/011)
    url_path = ttp_id.replace('.', '/')
    url = BASE_TECHNIQUE_URL.format(ttp_id=url_path)
    try:
        response = session.get(url, timeout=12)
        if response.status_code != 200:
            return ""
    except requests.RequestException:
        return ""

    soup = BeautifulSoup(response.text, "html.parser")
    detection_heading = None
    for heading in soup.find_all(["h2", "h3"]):
        if "detection" in heading.get_text(" ", strip=True).lower():
            detection_heading = heading
            break

    if not detection_heading:
        return ""

    chunks: List[str] = []
    current = detection_heading.find_next_sibling()
    while current and current.name not in {"h2", "h3"}:
        if current.name == "table":
            # THIS FIXES THE MUSHED TEXT ISSUE
            table_md = table_to_markdown(current)
            if table_md:
                chunks.append(table_md)
        else:
            text = current.get_text(" ", strip=True)
            if text:
                chunks.append(text)
        current = current.find_next_sibling()

    return "\n\n".join(chunks).strip()

def format_document(description: str, mitigations: str, deep_detection_text: str) -> str:
    return (
        "### DESCRIPTION ###\n"
        f"{(description or '').strip()}\n"
        "### MITIGATIONS ###\n"
        f"{(mitigations or '').strip()}\n"
        "### DETECTIONS ###\n"
        f"{(deep_detection_text or '').strip()}"
    )

def wipe_collection() -> None:
    existing = mitre_info.get()
    ids = existing.get("ids", []) if existing else []
    if ids:
        mitre_info.delete(ids=ids)

def upload_enriched_mitre_data(csv_path: str = CSV_PATH) -> Tuple[int, int]:
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"{csv_path} was not found.")

    wipe_collection()

    ids: List[str] = []
    documents: List[str] = []
    metadatas: List[Dict[str, str]] = []

    session = requests.Session()
    session.headers.update({"User-Agent": "BeyondTheAtomics-MITRE-Enricher/1.1"})

    with open(csv_path, mode="r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            ttp_id = (row.get("ID") or "").strip()
            name = (row.get("Name") or "").strip()
            description = row.get("Description") or ""
            mitigations = row.get("Mitigations") or ""
            detection = row.get("Detection") or ""

            if not ttp_id:
                continue

            normalized_mitigations = mitigations.strip()
            if normalized_mitigations.lower() == "none":
                normalized_mitigations = ""

            source_detection = detection.strip()
            if not source_detection or source_detection.lower() == "none":
                source_detection = scrape_technique_detection(ttp_id, session)

            deep_parts: List[str] = [source_detection] if source_detection else []
            for det_id in parse_detection_ids(source_detection):
                print(f"[*] Scraping {ttp_id} -> {det_id}")
                scraped_data = scrape_detection_strategy(det_id, session)
                if scraped_data:
                    deep_parts.append(scraped_data)

            deep_detection_text = "\n\n".join(part for part in deep_parts if part).strip()
            document = format_document(description, normalized_mitigations, deep_detection_text)

            ids.append(ttp_id)
            documents.append(document)
            metadatas.append({"id": ttp_id, "name": name})

    batch_size = 100
    for i in range(0, len(ids), batch_size):
        mitre_info.add(
            ids=ids[i : i + batch_size],
            documents=documents[i : i + batch_size],
            metadatas=metadatas[i : i + batch_size],
        )
        print(f"[+] Uploaded batch {(i // batch_size) + 1}")

    print(f"[+] Completed upload of {len(ids)} MITRE techniques.")
    return len(ids), len(ids)

if __name__ == "__main__":
    total, uploaded = upload_enriched_mitre_data()
    print(f"Done. parsed={total}, uploaded={uploaded}")