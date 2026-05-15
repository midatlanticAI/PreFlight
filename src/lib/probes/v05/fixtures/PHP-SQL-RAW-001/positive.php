<?php
// XL-002 / PHP-SQL-RAW-001 positive fixture.
// Superglobal concatenated into the SQL string.
function find_user($conn) {
    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
}
