<?php
/**
 * includes/iwb-sso-verify_signature.php
 * Plugin File header...
 * @todo Is there some sort of standard for this?
 */

/**
 * Slimmed down ECC library
 * There are no notes on this library.
 * but I got it from here: https://wordpress.org/plugins/web3-authentication/
 * It's a slimmed down version of :
 * @todo get that link at put it here
 * I'm not using composer for this yet as it creates some version conflicts.
 * So manual for now.
 */
require_once ('lib/Elliptic/EC.php');
require_once ('lib/Elliptic/Curves.php');

use Elliptic\EC;
use Tuupola\Base58;

/**
 * Some testing variables
 */
// $message = "Signing this message confirms you are who you say you are. Please confirm this dialog to sign this message and authorize your login. Message number: 7bc87bcdf2";
// $signature = "1f64bd92f912d97156e5caf95df0abff1f7faa8cea3590e9b94efedccb38e799d017233b7c1a65a430b67c2bd566b46f84c84396e3f36dee66b206806f12133673";
// $address = "STM852gdYeYEK47KkHs55mMufgQejB1BMia15JmcDX2UTavP99RZz";

//my_testing_header();

//iwb_sso_verify_message_signature($message, $signature, $address);

//my_testing_footer();

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

    // Strip 'STM'
    $stripKey = substr($hivePublicKey, 3);

    //color_red("base58 decoded key: ");
    $base58 = new Base58(["characters" => Base58::BITCOIN]);
    $decoded = $base58->decode($stripKey);
    $hexDecoded = bin2hex($decoded);
    //var_dump($hexDecoded);    

    // Check if key is compressed (it probably is)
    // if so, decompress and send to EC to derivce y
    if (substr($hexDecoded,0,2)== '04') {
        //color_red("not compressed");
        return $hexDecoded;
    } elseif (substr($hexDecoded,0,2) == '02'|'03') {
        //color_red("compressed, let's uncompress \n");
        $hexDecoded = substr($hexDecoded,0,66);
        $key = $ec->keyFromPublic($hexDecoded, 'hex');
        //print_r($key);

        //$test = $key->getPublic();
        // $x = $key->x;
        // $y = $key->y;
        //print_r($test);
        
        //$myText = var_export($test->getX(),true);
        
        // echo $myText;
        // var_dump($test->getX());
        // var_dump($test->getY());

        
        // $y = hex2String($test->getY());
        //echo '04'.$x.$y;
        //echo "\n";
    }
 
    // let's hash the message - that is what is actually signed
    $msgHash = openssl_digest($message, 'SHA256' );

    // now lets extract 'r' and 's' from the provided signature into an array
    $sig   = [
        "r" => substr($signature, 2, 64),
        "s" => substr($signature, 66, 64)
    ];

    // I am manually setting the recovery parameter
    //$recovery_parameter = ord(hex2bin(substr($signature, 130, 2))) - 28;
    $recovery_parameter = 0;    

    // very the message signature key against the formatted public key pair
    // echo "Verified: " . (($key->verify($msgHash, $sig) == TRUE) ? "true" : "false") . "\n";
    
    $valid = $key->verify($msgHash, $sig); 
    return $valid;

    // $response = array(
    //     'testing'  => 'Here???',
    //     'stripped key' => $stripKey,
    //     'valid:'  => $valid
    //   );
    
    //   wp_send_json($response);
    //   wp_die();


    // Get the public key from the signature
    // $pubkey = $ec->recoverPubKey($msgHash, $sig, $recovery_parameter);

    // formatting as a 'key pair'
    // $key = $ec->keyFromPublic($pubkey, 'hex');
    //var_dump($key);
    // echo $pubkey->inspect();
    //var_dump($pubkey->__debugInfo()) ;
    
    // we need to verify that the public key we are getting from the signature
    // is the same as the key we looked up: $hivePublicKey

    // I either need to 'form' the derived public key and check it against the 'given' public key verified by the block chain...
    // or
    // deconstruct the 'given' public key into it's 04 + x + y
    // Let's learn how to do both...

}

function sample_ssl_verify ($message) {
    /**
     * https://stackoverflow.com/questions/53183043/need-help-understanding-php-signature-verification
     * 
     */

    // $ssl_methods= openssl_get_md_methods();
    // print_r ($ssl_methods);

    $msg = $message;

    // Verify signature (use the same algorithm used to sign the msg).
    $result = openssl_verify($msg, base64_decode($signature), $key, OPENSSL_ALGO_SHA256);

        if ($result == 1)
    {
        $result = "Verified";
    }
    elseif ($result == 0)
    {
        $result = "Unverified";
    }
    else
    {
        $result = "Unknown verification response";
    }

    // Get base64 encoded public key.
    // NOTE: this is just for testing the code, final production code stores the public key in a db.
    $pubkey = $_POST['pubkey'];

    // Convert pubkey in to PEM format (don't forget the line breaks).
    $pubkey_pem = "-----BEGIN PUBLIC KEY-----\n$pubkey\n-----END PUBLIC KEY-----";

    // Get public key.
    $key = openssl_pkey_get_public($pubkey_pem);

    if ($key == 0)
    {
        $result = "Bad key zero.";
    }
    elseif ($key == false)
    {
        $result = "Bad key false.";
    }
    else
    {
        // Verify signature (use the same algorithm used to sign the msg).
        $result = openssl_verify($msg, base64_decode($signature), $key, OPENSSL_ALGO_SHA256);

        if ($result == 1)
        {
            $result = "Verified";
        }
        elseif ($result == 0)
        {
            $result = "Unverified";
        }
        else
        {
            $result = "Unknown verification response";
        }
        // do something with the result.
    }
    /**
     * end of this testing code
    * 
    */
}

/**
 * My testing header
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
