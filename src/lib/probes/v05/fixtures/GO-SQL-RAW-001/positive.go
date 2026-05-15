// XL-002 / GO-SQL-RAW-001 positive fixture.
// SQL string built with fmt.Sprintf and passed to db.Query.
package store

func GetUser(db *sql.DB, id string) (*sql.Rows, error) {
	return db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
}
