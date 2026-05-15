<?php
// XL-006 / PHP-SECRETS-001 positive fixture.
// Credential-named variable assigned a literal (synthetic, low-entropy).
class ApiClient {
    public function key() {
        $apiKey = "AAAAAAAAAAAAAAAAAAAAAAAA";
        return $apiKey;
    }
}
