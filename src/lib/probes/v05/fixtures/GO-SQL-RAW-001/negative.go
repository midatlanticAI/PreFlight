// XL-002 / GO-SQL-RAW-001 negative fixture.
// Placeholder parameter: the value is bound, not formatted in.
package store

func GetUser(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE id = $1", id)
}
