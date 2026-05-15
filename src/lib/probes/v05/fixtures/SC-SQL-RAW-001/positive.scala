// XL-002 / SC-SQL-RAW-001 positive fixture.
// Slick #${} performs literal interpolation: textbook injection.
object UserRepo {
  def find(name: String) =
    sql"SELECT * FROM users WHERE name = '#${name}'".as[String]
}
