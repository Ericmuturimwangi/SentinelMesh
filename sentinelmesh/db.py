from flask import current_app, g
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


def init_pool(app) -> ConnectionPool:
    pool = ConnectionPool(
        conninfo=app.config["DATABASE_URL"],
        min_size=1,
        max_size=8,
        kwargs={"row_factory": dict_row},
        open=True,
    )
    app.extensions["db_pool"] = pool
    app.teardown_appcontext(_release_connection)
    return pool


def _release_connection(exception):
    conn = g.pop("db_conn", None)
    if conn is None:
        return
    if exception is not None:
        conn.rollback()
    else:
        conn.commit()
    current_app.extensions["db_pool"].putconn(conn)


def connection():
    """One connection per request, committed on a clean teardown."""
    if "db_conn" not in g:
        g.db_conn = current_app.extensions["db_pool"].getconn()
    return g.db_conn
