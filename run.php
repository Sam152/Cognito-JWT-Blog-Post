<?php

require_once 'vendor/autoload.php';

[, $region, $poolId, $clientId, $type, $token] = $argv;

$config = new \Sam\JwtBlogPost\CognitoConfiguration($region, $poolId, $clientId);
$keyManager = new \Sam\JwtBlogPost\CognitoKeyManager(
    new \GuzzleHttp\Client(),
    $config,
);
$decoder = new \Sam\JwtBlogPost\CognitoJwtDecoder($keyManager, $config);

var_export($type === 'access' ? $decoder->decodeAccessToken($token) : $decoder->decodeIdToken($token));
