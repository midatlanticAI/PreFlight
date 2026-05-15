/* XL-002 / CC-SQL-RAW-001 negative fixture.
   Prepared statement with a bound parameter. */
int get_user(sqlite3 *db, const char *uid, sqlite3_stmt **stmt) {
    int rc = sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, stmt, 0);
    sqlite3_bind_text(*stmt, 1, uid, -1, SQLITE_TRANSIENT);
    return rc;
}
