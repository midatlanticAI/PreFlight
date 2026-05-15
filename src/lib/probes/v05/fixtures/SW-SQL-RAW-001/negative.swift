// XL-002 / SW-SQL-RAW-001 negative fixture.
// Bound parameter via FMDB executeUpdate with a ? placeholder.
func findUser(_ db: FMDatabase, _ uid: String) throws {
    try db.executeUpdate("SELECT * FROM users WHERE id = ?", values: [uid])
}
