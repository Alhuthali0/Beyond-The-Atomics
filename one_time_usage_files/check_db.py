from app import app
from tools.models import SimulationResult, Schedule
with app.app_context():
    sims = SimulationResult.query.all()
    print(f"SimulationResults: {len(sims)}")
    for r in sims[:5]:
        print(f"  - {r.ttp_id} ({r.ttp_name})")
    
    schs = Schedule.query.all()
    print(f"Schedules: {len(schs)}")
    for s in schs[:5]:
        print(f"  - {s.ttp_id} ({s.test_guid})")
