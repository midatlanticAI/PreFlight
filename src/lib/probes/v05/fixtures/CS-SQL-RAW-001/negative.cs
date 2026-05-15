// XL-002 / CS-SQL-RAW-001 negative fixture.
// Parameterized command; the value is bound, not interpolated.
public class Repo {
    public SqlCommand Find(SqlConnection conn, string name) {
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @n", conn);
        cmd.Parameters.AddWithValue("@n", name);
        return cmd;
    }
}
