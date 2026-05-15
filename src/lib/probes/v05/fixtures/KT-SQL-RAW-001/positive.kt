// XL-002 / KT-SQL-RAW-001 positive fixture.
// Room SimpleSQLiteQuery built by concatenation.
fun findUser(dao: UserDao, name: String): List<User> {
    val q = SimpleSQLiteQuery("SELECT * FROM user WHERE name = '" + name + "'")
    return dao.raw(q)
}
