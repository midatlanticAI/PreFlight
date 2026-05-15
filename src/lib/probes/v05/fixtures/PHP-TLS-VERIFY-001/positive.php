<?php
// XL-004 / PHP-TLS-VERIFY-001 positive fixture.
// curl peer verification disabled.
function client($ch) {
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    return $ch;
}
