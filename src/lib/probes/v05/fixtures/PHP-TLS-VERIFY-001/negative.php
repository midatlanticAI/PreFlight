<?php
// XL-004 / PHP-TLS-VERIFY-001 negative fixture.
// Peer verification on; explicit CA bundle.
function client($ch) {
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_CAINFO, "/etc/ssl/certs/ca.pem");
    return $ch;
}
