<?php

namespace Sam\JwtBlogPost;

use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Sam\JwtBlogPost\Checkers\ClientIdChecker;
use Sam\JwtBlogPost\Checkers\TokenUseChecker;

/**
 * Load and verify Cognito tokens.
 *
 * Rules for verifying tokens are:
 *  - Verify that the token is not expired.
 *  - The aud claim in an ID token and the client_id claim in an access token should match the app client ID that was created in the Amazon Cognito user pool.
 *  - The issuer (iss) claim should match your user pool. For example, a user pool created in the us-east-1 Region will have the following iss value: https://cognito-idp.us-east-1.amazonaws.com/<userpoolID>.
 *  - Check the token_use claim.
 *    - If you are only accepting the access token in your web API operations, its value must be access.
 *    - If you are only using the ID token, its value must be id.
 *    - If you are using both ID and access tokens, the token_use claim must be either id or access.
 *
 * @see https://web-token.spomky-labs.com/advanced-topics-1/security-recommendations#loading-process
 * @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
 */
class CognitoJwtDecoder {
    public function __construct(private CognitoKeyManager $keyManager, private CognitoConfiguration $configuration) {
    }

    public function decodeIdToken(string $token): JWS {
        return $this->decodeAndValidate($token, [
            new AudienceChecker($this->configuration->clientId),
            new TokenUseChecker('id'),
        ], ['iss', 'aud', 'token_use']);
    }

    public function decodeAccessToken(string $token): JWS {
        return $this->decodeAndValidate($token, [
            new ClientIdChecker($this->configuration->clientId),
            new TokenUseChecker('access'),
        ], ['iss', 'client_id', 'token_use']);
    }

    /**
     * @throws \Jose\Component\Checker\InvalidClaimException
     * @throws \Jose\Component\Checker\MissingMandatoryClaimException
     * @throws \Exception
     */
    private function decodeAndValidate(string $token, array $claimChecks, array $mandatoryClaims): JWS {
        $headerChecker = new HeaderCheckerManager([new AlgorithmChecker(['RS256'])], [new JWSTokenSupport()]);
        $claimChecker = new ClaimCheckerManager(
            array_merge([
                new IssuedAtChecker(),
                new NotBeforeChecker(),
                new ExpirationTimeChecker(),
                new IssuerChecker([$this->configuration->getIssuer()]),
            ], $claimChecks)
        );

        $loader = new JWSLoader(new JWSSerializerManager([new CompactSerializer()]), new JWSVerifier(new AlgorithmManager([new RS256()])), $headerChecker);
        $jws = $loader->loadAndVerifyWithKeySet($token, $this->keyManager->getKeySet($token), $signature);

        $claims = json_decode($jws->getPayload(), true);
        $claimChecker->check($claims, $mandatoryClaims);

        return $jws;
    }

}
