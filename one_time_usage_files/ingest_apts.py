import json
import uuid
import re
from app import app, db, APTGroup, APTTTP

def ingest_apts():
    with app.app_context():
        # Clear old
        APTTTP.query.delete()
        APTGroup.query.delete()
        db.session.commit()
        
        with open('apt_groups_mapped.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        group_count = 0
        ttp_count = 0
        for item in data:
            name = item.get('name', 'Unknown Group')
            description = item.get('description', '')
            aliases = ", ".join(item.get('aliases', []))
            
            # Try to extract GXXXX ID from description
            match = re.search(r'groups/(G\d{4})', description)
            if match:
                apt_id = match.group(1)
            else:
                apt_id = f"custom_{uuid.uuid4().hex[:8]}"
            
            # Ensure unique ID
            while APTGroup.query.get(apt_id):
                apt_id = f"custom_{uuid.uuid4().hex[:8]}"
            
            new_group = APTGroup(
                id=apt_id,
                name=name,
                aliases=aliases,
                description=description
            )
            db.session.add(new_group)
            group_count += 1
            
            used_ttps = item.get('used_ttps', [])
            # use a set to avoid duplicate TTPs per group
            seen_ttps = set()
            for ttp in used_ttps:
                ttp_id = ttp.get('ttp_id')
                if ttp_id and ttp_id not in seen_ttps:
                    seen_ttps.add(ttp_id)
                    new_ttp = APTTTP(
                        apt_id=apt_id,
                        ttp_id=ttp_id
                    )
                    db.session.add(new_ttp)
                    ttp_count += 1
                    
        db.session.commit()
        print(f"Successfully ingested {group_count} APT Groups and {ttp_count} TTP mappings.")

if __name__ == '__main__':
    ingest_apts()