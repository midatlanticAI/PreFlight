<?php
// XL-006 / PHP-SECRETS-001 negative fixture.
// Key read from the environment, not bound to a literal.
class ApiClient {
    public function key() {
        $apiKey = getenv("OPENAI_API_KEY");
        return $apiKey;
    }
}
