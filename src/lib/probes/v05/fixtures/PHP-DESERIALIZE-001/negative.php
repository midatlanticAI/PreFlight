<?php
// XL-001 / PHP-DESERIALIZE-001 negative fixture.
// unserialize with allowed_classes disabled.
function load_session($data) {
    return unserialize($data, ['allowed_classes' => false]);
}
