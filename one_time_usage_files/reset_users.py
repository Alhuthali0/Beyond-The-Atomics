from app import db, app, User
from werkzeug.security import generate_password_hash

with app.app_context():
    print("[*] Wiping User table...")
    User.query.delete()
    db.session.commit()
    
    print("[*] Creating default admin account...")
    hashed_pw = generate_password_hash('admin', method='pbkdf2:sha256')
    admin = User(
        full_name='System Admin', 
        email='admin@beyond-atomics.internal', 
        username='admin', 
        password=hashed_pw, 
        role='admin', 
        status='approved'
    )
    db.session.add(admin)
    db.session.commit()
    print("✅ Database reset complete. Admin user created.")
