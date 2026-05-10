import os
import sqlite3
import urllib.request


def execute_query(query):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    return cursor.execute(query)


def path_traversal(name):
    path = os.path.join("/tmp/uploads", name)
    return open(path).read()


def sql_injection(user_id):
    query = "select * from users where id = " + user_id
    return execute_query(query)


def code_injection(expr):
    return eval(expr)


def ssrf(url):
    return urllib.request.urlopen(url).read()


def main():
    value = input("value: ")
    path_traversal(value)
    query = value
    execute_query(query)
    code_injection(value)
    ssrf(value)


if __name__ == "__main__":
    main()
