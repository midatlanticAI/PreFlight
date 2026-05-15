# Positive fixture for PY-SQL-RAW-001 (XL-002 Raw Query Interpolation).
# Each line below MUST be flagged.

from django.db import connection
from django.db.models.expressions import RawSQL
from sqlalchemy import text


def search_users(name):
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
        return cursor.fetchall()


def filter_orders(User, status):
    return User.objects.extra(where=[f"status = '{status}'"])


def raw_lookup(User, uid):
    return User.objects.raw(f"SELECT * FROM users WHERE id = {uid}")


def sa_lookup(session, user_id):
    return session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))


def percent_built(cursor, name):
    cursor.execute("SELECT * FROM t WHERE name = '%s'" % name)
