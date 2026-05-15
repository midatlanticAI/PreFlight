// XL-002 / CPP-SQL-RAW-001 positive fixture.
// Qt QSqlQuery exec with a QString(...).arg(...) built query.
bool findUser(QSqlQuery &query, const QString &uid) {
    return query.exec(QString("SELECT * FROM users WHERE id = %1").arg(uid));
}
