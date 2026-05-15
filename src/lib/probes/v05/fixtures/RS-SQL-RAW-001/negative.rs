// XL-002 / RS-SQL-RAW-001 negative fixture.
// Bound parameter: the value is sent separately, not formatted in.
pub async fn get_user(pool: &Pool, id: &str) -> Vec<Row> {
    sqlx::query("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_all(pool)
        .await
        .unwrap()
}
