<?php
/**
 * includes/tests.php
 * This is a mostly self contained (runs outside of workdpress), test file for testing Hive signature verification.
 * It does require the libraries noted below in dependencies in right locations. 
 * This is a test file for iwb-sso-verify_signature.php, it is only a test file.
 * to run: php path/tests.php
 * 
 * @todo Is there some sort of standard for header comments?
 */


/**
 * Dependencies:
 * I am using Composer, a php 'packaging/dependency' tool to manage and load libraries where I can.
 * Currently that's only Tuupola\Base58, a Base58 encoding/decoding library.
 * This is also dependent on a slimmed down ECC library, elliptic. There are no notes inside this library.
 * but I got it from this WordPress plugin here: https://wordpress.org/plugins/web3-authentication/
 * It's a slimmed down version of : https://github.com/simplito/elliptic-php/ , 
 * which itself is a port of https://github.com/indutny/elliptic
 * I'm not using composer for this library yet as it creates some version conflicts using the full elliptic-php
 * So manual for now, it's included in the plugin files under lib.
 */

// This is a composer thing...
// but the path is altered so it will run, this is just a test file.
require '../vendor/autoload.php';

/**
 * Custom includes outside of composer
 */
require_once ('lib/Elliptic/EC.php');
require_once ('lib/Elliptic/Curves.php');

use Elliptic\EC;
use Tuupola\Base58;

/**
 * Some testing variables
 */
$message = "Signing this message confirms you are who you say you are. Please confirm this dialog to sign this message and authorize your login. Message number: 7bc87bcdf2";
$signature = "1f64bd92f912d97156e5caf95df0abff1f7faa8cea3590e9b94efedccb38e799d017233b7c1a65a430b67c2bd566b46f84c84396e3f36dee66b206806f12133673";
$address = "STM852gdYeYEK47KkHs55mMufgQejB1BMia15JmcDX2UTavP99RZz";

my_testing_header();

iwb_sso_verify_message_signature($message, $signature, $address);

my_testing_footer();

/**
 * function iwb_sso_verify_message_signature ($message, $signature, $hivePublicKey)
 * Verify a signed message
 * 
 * @param   string  $message        the message that has been signed
 * @param   string  $signature      the signature
 * @param           $hivePublicKey  the public key of the signer i.e: 
 * "STM852gdYeYEK47KkHs55mMufgQejB1BMia15JmcDX2UTavP99RZz"
 */
function iwb_sso_verify_message_signature ($message, $signature, $hivePublicKey) {

    // let's first instantinate a new EC Object from EC
    // We will use it as we go.
    $ec = new EC('secp256k1');

    color_red("Public key from Hive lookup: ");
    var_dump($hivePublicKey);

    // Strip 'STM'
    $stripKey = substr($hivePublicKey, 3);
    // echo $stripKey;
    // echo "\n";

    color_red("base58 decoded key: ");
    $base58 = new Base58(["characters" => Base58::BITCOIN]);
    $decoded = $base58->decode($stripKey);
    $hexDecoded = bin2hex($decoded);
    var_dump($hexDecoded);

    // Check if key is compressed
    // Hive's keys are pretty much always compressed,
    // See here for reference: https://github.com/holgern/beem/blob/master/beemgraphenebase/account.py 
    // note:: By default, graphene-based networks deal with **compressed**
    // public keys.

    // if so, decompress and send to EC to derive y
    if (substr($hexDecoded,0,2)== '04') {
        color_red("not compressed");
        return $hexDecoded;
        // do something different here
        // Hive's keys are pretty much always compressed
    } elseif (substr($hexDecoded,0,2) == '02'|'03') {
        color_red("compressed, let's uncompress \n");
        $hexDecoded = substr($hexDecoded,0,66);
        $key = $ec->keyFromPublic($hexDecoded, 'hex');
        //print_r($key);
        $test = $key->getPublic();
        print_r($test);
        // var_dump($test->getX());
        // var_dump($test->getY());
    }
 
    // let's hash the message - that is what is actually signed
    $msgHash = openssl_digest($message, 'SHA256' );

    // now lets extract 'r' and 's' from the provided signature into an array
    $sig   = [
        "r" => substr($signature, 2, 64),
        "s" => substr($signature, 66, 64)
    ];
    color_red("Signature r, and s: \n");
    var_dump($sig);
    echo "\n";

    // very the message signature key against the formatted public key pair using the ECC library's verify method.
    color_red("Is the signature verified: ");
    echo "Verified: " . (($key->verify($msgHash, $sig) == TRUE) ? "true" : "false") . "\n";

    // Still working on reconstructing the public key from the signature
    // $pubkey = $ec->recoverPubKey($msgHash, $sig, $recovery_parameter);
}

/**
 * My testing header
 * This test script is intedned to be run from command line
 * These make fancy colors on command line.
 */
function my_testing_header () {
    system('clear');
    echo "\e[0;31mBegin Testing: \e[0m";
    echo "begin*************  ";
    echo "\e[0;32mMerry \e[0;31mChristmas!\e[0m\n";
}

/**
 * My testing footer
 */
function my_testing_footer () {

    color_red("\n******END\n");

}

/**
 * My color notation function for fun
 */
function color_red($echo_text) {
    echo "\e[0;31m$echo_text\e[0m";
}

?>
