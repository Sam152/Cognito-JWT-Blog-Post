<?php

declare(strict_types=1);

namespace Sam\JwtBlogPost;

use GuzzleHttp\ClientInterface;
use Jose\Component\Core\JWKSet;

class CognitoKeyManager {
    public function __construct(private ClientInterface $client, private CognitoConfiguration $configuration) {
    }

    public function getKeySet(): JWKSet {
        return JWKSet::createFromJson($this->retrieveKeys());
    }

    private function retrieveKeys(): string {
        // @todo These keys can be cached.
        return (string) $this->client->request('GET', $this->configuration->getPublicKeysUrl())->getBody();
    }
}
