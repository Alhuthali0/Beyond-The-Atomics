import sqlite3
import os

def upgrade_db():
    # Search in common locations
    possible_paths = [
        os.path.join("My_Version", "instance", "users.db"),
        os.path.join("instance", "users.db"),
        "users.db"
    ]
    
    db_path = None
    for path in possible_paths:
        if os.path.exists(path):
            db_path = path
            break

    if not db_path:
        print(f"[!] Database not found. Checked: {possible_paths}")
        return

    # 1. Update simulation_result table
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    columns_to_add = [
        ("wazuh_severity", "TEXT"),
        ("wazuh_rule_desc", "TEXT"),
        ("ai_reasoning", "TEXT"),
        ("test_name", "TEXT")
    ]

    for col_name, col_type in columns_to_add:
        print(f"[*] Attempting to add column: {col_name}")
        try:
            cursor.execute(f"ALTER TABLE simulation_result ADD COLUMN {col_name} {col_type}")
            conn.commit()
            print(f"[+] Successfully added {col_name}")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e).lower():
                print(f"[-] Column {col_name} already exists. Skipping.")
            else:
                print(f"[X] Error adding column {col_name}: {e}")

    # 2. Update atomic_test table
    print("[*] Checking atomic_test table for elevation_required and user_context...")
    try:
        cursor.execute("ALTER TABLE atomic_test ADD COLUMN elevation_required BOOLEAN DEFAULT 0")
        conn.commit()
        print("[+] Successfully added elevation_required to atomic_test")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("[-] Column elevation_required already exists in atomic_test. Skipping.")
        else:
            print(f"[X] Error adding column elevation_required to atomic_test: {e}")

    try:
        cursor.execute("ALTER TABLE atomic_test ADD COLUMN user_context TEXT")
        conn.commit()
        print("[+] Successfully added user_context to atomic_test")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print("[-] Column user_context already exists in atomic_test. Skipping.")
        else:
            print(f"[X] Error adding column user_context to atomic_test: {e}")

    conn.close()
    print("[*] Migration script completed.")

if __name__ == "__main__":
    upgrade_db()
