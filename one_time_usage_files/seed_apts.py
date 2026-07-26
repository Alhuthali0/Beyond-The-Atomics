from db import apt_info
import uuid

# A curated list of well-known APT groups and their characteristic TTPs
APT_SEED_DATA = [
    {
        "name": "APT29 (Cozy Bear)",
        "description": "A Russian-based threat group suspected of being associated with the SVR. Known for stealthy long-term espionage and high-profile targets.",
        "ttps": ["T1059.001", "T1071.001", "T1082", "T1083", "T1543.003", "T1562.001", "T1548.002"]
    },
    {
        "name": "Lazarus Group",
        "description": "A North Korean state-sponsored threat group known for both cyberespionage and financially motivated attacks (e.g., SWIFT heist).",
        "ttps": ["T1059.003", "T1027", "T1071.001", "T1082", "T1547.001", "T1053.005", "T1132.001"]
    },
    {
        "name": "FIN7",
        "description": "A prolific financially motivated threat group that has targeted the retail, restaurant, and hospitality sectors since at least 2015.",
        "ttps": ["T1059.001", "T1059.005", "T1204.002", "T1027", "T1071.001", "T1543.003", "T1082"]
    },
    {
        "name": "APT41",
        "description": "A prolific Chinese state-sponsored group that also conducts financially motivated activity. Known for software supply chain attacks.",
        "ttps": ["T1059.003", "T1053.005", "T1071.001", "T1547.001", "T1082", "T1027", "T1105"]
    },
    {
        "name": "Wizard Spider (Ryuk/Conti)",
        "description": "A Russia-based financially motivated threat group known for high-impact ransomware-as-a-service operations.",
        "ttps": ["T1486", "T1059.001", "T1482", "T1003.001", "T1021.001", "T1047", "T1135"]
    }
]

def seed_apts():
    print("[*] Seeding known APT groups into database...")
    
    # Clear existing if any
    existing = apt_info.get()
    if existing['ids']:
        apt_info.delete(ids=existing['ids'])
    
    ids = []
    documents = []
    metadatas = []
    
    for apt in APT_SEED_DATA:
        apt_id = str(uuid.uuid4())
        ids.append(apt_id)
        # Store description and TTP list in document for searchability
        documents.append(f"Group: {apt['name']}\nDescription: {apt['description']}\nTTPs: {', '.join(apt['ttps'])}")
        metadatas.append({
            "name": apt['name'],
            "ttps": ",".join(apt['ttps'])
        })
    
    apt_info.add(
        ids=ids,
        documents=documents,
        metadatas=metadatas
    )
    
    print(f"✅ Successfully seeded {len(ids)} APT groups.")

if __name__ == "__main__":
    seed_apts()
