// XL-002 / RS-SQL-RAW-001 positive fixture.
// SQLx runtime query with the value format!-ed into the SQL string.
pub async fn get_user(pool: &Pool, id: &str) -> Vec<Row> {
    sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id))
        .fetch_all(pool)
        .await
        .unwrap()
}
