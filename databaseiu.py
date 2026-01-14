import sqlite3 as sq3
import datetime 

DB_PATH = "data/pguard.db" #!!! удобная темка чтобы не было беспорядка... :(

def init_db():
    
    #data folder init!!! ...
    import os
    if not os.path.exists('data'):
        os.makedirs('data')
    
    conn = sq3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("create table if not exists users(user_id INTEGER PRIMARY KEY, username TEXT, role TEXT DEFAULT 'user', reg_date TEXT)")
    conn.commit()
    conn.close()


def register_user(user_id, username):

    conn = sq3.connect(DB_PATH)
    cursor = conn.cursor()
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute("INSERT OR IGNORE INTO users (user_id, username, reg_date) VALUES (?, ?, ?)",(user_id, username, now))
    
    conn.commit()
    conn.close()