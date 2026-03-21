"""CWE-89: SQL Injection in Python
String formatting used to build SQL queries with user input."""

import sqlite3
import sys


def find_user(db, username):
    """SQL injection via f-string."""
    cursor = db.cursor()
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()


def search_products(db, category, min_price):
    """SQL injection via .format()."""
    cursor = db.cursor()
    query = "SELECT * FROM products WHERE category = '{}' AND price > {}".format(
        category, min_price
    )
    cursor.execute(query)
    return cursor.fetchall()


def delete_record(db, record_id):
    """SQL injection via % formatting."""
    cursor = db.cursor()
    query = "DELETE FROM records WHERE id = %s" % record_id
    cursor.execute(query)
    db.commit()


def main():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER, name TEXT, role TEXT)")
    db.execute("INSERT INTO users VALUES (1, 'admin', 'admin')")
    db.execute("CREATE TABLE products (id INTEGER, category TEXT, price REAL)")
    db.execute("CREATE TABLE records (id INTEGER, data TEXT)")
    db.commit()

    if len(sys.argv) > 1:
        results = find_user(db, sys.argv[1])
        print(f"Found: {results}")

    db.close()


if __name__ == "__main__":
    main()
