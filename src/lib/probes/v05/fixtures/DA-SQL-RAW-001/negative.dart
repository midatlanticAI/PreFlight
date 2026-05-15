// XL-002 / DA-SQL-RAW-001 negative fixture.
// ? placeholder with an args list: the value is bound, not interpolated.
Future<List<Map<String, Object?>>> findUser(Database db, String name) {
  return db.rawQuery('SELECT * FROM users WHERE name = ?', [name]);
}
