import sqlite3

def init_db():
    conn = sqlite3.connect('scans.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            registrar TEXT,
            ip_address TEXT,
            ssl_status TEXT,
            risk_level TEXT,
            risk_score INTEGER,
            country TEXT,
            city TEXT,
            isp TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database created successfully!")