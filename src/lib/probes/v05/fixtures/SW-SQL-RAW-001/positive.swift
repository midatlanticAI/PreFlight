// XL-002 / SW-SQL-RAW-001 positive fixture.
// SQL string built with Swift \(...) interpolation.
func findUser(_ db: Connection, _ uid: String) throws {
    try db.execute("SELECT * FROM users WHERE id = \(uid)")
}
