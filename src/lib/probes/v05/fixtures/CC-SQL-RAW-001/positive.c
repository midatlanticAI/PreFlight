/* XL-002 / CC-SQL-RAW-001 positive fixture.
   sqlite3_mprintf with %s (not the safe %q) splices the value into SQL. */
char *build_query(const char *uid) {
    return sqlite3_mprintf("SELECT * FROM users WHERE id = %s", uid);
}
