<?php

require "./src/EncUtils.php";
require "./src/EncryptException.php";

use Oonix\Encryption\EncUtils;

$enc = new EncUtils("c6ZTakOudbvu7aad", "AES-128-CBC");

define('PLAIN', "The quick brown fox jumped over the lazy dog.");

echo "<h3>Return as a concatenated string, or an array</h3>";
var_dump($enc->encrypt(PLAIN));
var_dump($enc->encrypt(PLAIN, true));

echo "<h3>Return as raw binary data</h3>";
$enc->config('openssl_options', OPENSSL_RAW_DATA);
var_dump($enc->encrypt(PLAIN));

echo "<h3>Decrypt detects array or string input</h3>";
var_dump($enc->decrypt($enc->encrypt(PLAIN)));
var_dump($enc->decrypt($enc->encrypt(PLAIN, true)));

?>
