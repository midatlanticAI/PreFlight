// XL-002 / CPP-SQL-RAW-001 negative fixture.
// Prepared query with a bound placeholder.
bool findUser(QSqlQuery &query, const QString &uid) {
    query.prepare("SELECT * FROM users WHERE id = :id");
    query.bindValue(":id", uid);
    return query.exec();
}
