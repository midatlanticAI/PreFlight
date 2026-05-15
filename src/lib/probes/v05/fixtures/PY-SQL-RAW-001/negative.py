# Negative fixture for PY-SQL-RAW-001. NONE of these should fire.
# Parameterized / bound forms only.

from django.db import connection
from sqlalchemy import text


def search_users(name):
    with connection.cursor() as cursor:
        # bound parameter, not interpolation
        cursor.execute("SELECT * FROM users WHERE name = %s", [name])
        return cursor.fetchall()


def filter_orders(User, status):
    # ORM filter: parameterized by the ORM
    return User.objects.filter(status=status)


def raw_lookup(User, uid):
    # raw with params= is safe
    return User.objects.raw("SELECT * FROM users WHERE id = %s", [uid])


def sa_lookup(session, user_id):
    # bindparams binds the value, no parse-time injection
    return session.execute(text("SELECT * FROM users WHERE id = :id").bindparams(id=user_id))


def literal_only(cursor):
    # literal query, no interpolation
    cursor.execute("SELECT 1")
