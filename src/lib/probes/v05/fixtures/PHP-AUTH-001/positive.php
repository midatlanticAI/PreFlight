<?php

use Lcobucci\JWT\Configuration;

final class TokenService
{
    public function config(): Configuration
    {
        return Configuration::forUnsecuredSigner();
    }

    public function subject(string $token): string
    {
        $claims = json_decode(base64_decode(explode('.', $token)[1]), true);
        return $claims['sub'];
    }
}
