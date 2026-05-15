// XL-002 / DA-SQL-RAW-001 positive fixture.
// sqflite rawQuery with the value interpolated into the SQL string.
Future<List<Map<String, Object?>>> findUser(Database db, String name) {
  return db.rawQuery('SELECT * FROM users WHERE name = "$name"');
}
