<?php

namespace Sam\JwtBlogPost;

class CognitoConfiguration {
    public function __construct(
        public readonly string $region,
        public readonly string $poolId,
        public readonly string $clientId,
    ) {
    }

    public function getIssuer(): string {
        return sprintf('https://cognito-idp.%s.amazonaws.com/%s_%s', $this->region, $this->region, $this->poolId);
    }

    public function getPublicKeysUrl(): string {
        return sprintf('https://cognito-idp.%s.amazonaws.com/%s_%s/.well-known/jwks.json', $this->region, $this->region, $this->poolId);
    }
}
