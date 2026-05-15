// XL-002 / SC-SQL-RAW-001 negative fixture.
// The ${} form binds the value as a parameter (no # prefix).
object UserRepo {
  def find(name: String) =
    sql"SELECT * FROM users WHERE name = ${name}".as[String]
}
