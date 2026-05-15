<?php
// XL-002 / PHP-SQL-RAW-001 negative fixture.
// Prepared statement with a bound parameter.
function find_user($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch();
}
