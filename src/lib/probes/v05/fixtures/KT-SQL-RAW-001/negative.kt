// XL-002 / KT-SQL-RAW-001 negative fixture.
// Room @Query with a :named binding.
@Dao
interface UserDao {
    @Query("SELECT * FROM user WHERE name = :name")
    fun findUser(name: String): List<User>
}
