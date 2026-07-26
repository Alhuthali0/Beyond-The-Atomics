import json
from app import app, db, TTPMitigation

def ingest_mitigations():
    with app.app_context():
        # Clear old
        TTPMitigation.query.delete()
        db.session.commit()
        
        with open('ttps_remediation_mapped.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        count = 0
        for item in data:
            ttp_id = item.get('mitre_id')
            mitigations = item.get('mitigations', [])
            for mit in mitigations:
                name = mit.get('name', 'Unknown')
                desc = mit.get('description', '')
                if ttp_id and name:
                    new_mit = TTPMitigation(
                        ttp_id=ttp_id,
                        mitigation_name=name,
                        description=desc
                    )
                    db.session.add(new_mit)
                    count += 1
                    
        db.session.commit()
        print(f"Successfully ingested {count} mitigations.")

if __name__ == '__main__':
    ingest_mitigations()
