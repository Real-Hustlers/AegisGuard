import mysql.connector

try:
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="YOUR_MYSQL_PASSWORD"
    )

    print("✅ Connected to MySQL!")

    cursor = conn.cursor()
    cursor.execute("SELECT VERSION();")

    for row in cursor:
        print("MySQL Version:", row[0])

    conn.close()

except Exception as e:
    print("❌ Error:", e)