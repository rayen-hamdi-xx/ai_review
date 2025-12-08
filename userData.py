import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    print(f"Executing query: {query}")
    cursor.execute(query)
    
    result = cursor.fetchall()
    conn.close()
    return result
