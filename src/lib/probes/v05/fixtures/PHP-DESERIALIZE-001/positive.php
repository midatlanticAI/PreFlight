<?php
// XL-001 / PHP-DESERIALIZE-001 positive fixture.
// unserialize on an untrusted cookie: PHP object injection.
function load_session() {
    return unserialize($_COOKIE['session']);
}
