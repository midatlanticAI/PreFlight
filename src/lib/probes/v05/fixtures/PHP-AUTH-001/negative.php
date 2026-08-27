<?php

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;

final class TokenService
{
    public function config(string $secret): Configuration
    {
        return Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText($secret));
    }
}
