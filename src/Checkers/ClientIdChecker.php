<?php

declare(strict_types=1);

namespace Sam\JwtBlogPost\Checkers;

use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\InvalidClaimException;

final class ClientIdChecker implements ClaimChecker {
    private const CLAIM_NAME = 'client_id';

    public function __construct(private string $clientId) {
    }

    /**
     * {@inheritdoc}
     */
    public function checkClaim(mixed $value): void {
        $this->checkValue($value, InvalidClaimException::class);
    }

    public function supportedClaim(): string {
        return self::CLAIM_NAME;
    }

    /**
     * @param class-string<\Exception> $class
     */
    private function checkValue(string $value, string $class): void {
        if ($value !== $this->clientId) {
            throw new $class('Bad client_id.', self::CLAIM_NAME, $value);
        }
    }
}
