// XL-002 / CS-SQL-RAW-001 positive fixture.
// Interpolated string into SqlCommand: not parameterized.
public class Repo {
    public SqlCommand Find(SqlConnection conn, string name) {
        return new SqlCommand($"SELECT * FROM Users WHERE Name = '{name}'", conn);
    }
}
