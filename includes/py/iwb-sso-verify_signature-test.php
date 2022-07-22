<?php

/**
 * This is a composer thing...
 * It includes all the dependencies defined by composer
 */
require '../../vendor/autoload.php';

/**
 * I'm running this in a test script... and so these files are normally here:
 * but they are different in my test enviornment.
 * I should look into using composer for these?
 */
// require_once ('includes/lib/Keccak/Keccak.php');
// require_once ('includes/lib/Elliptic/EC.php');
// require_once ('includes/lib/Elliptic/Curves.php');

// Testing: where these files are in my testing enviornment
require_once ('../../includes/lib/Keccak/Keccak.php');
require_once ('../../includes/lib/Elliptic/EC.php');
require_once ('../../includes/lib/Elliptic/Curves.php');

use Elliptic\EC;
use kornrunner\Keccak;
use Tuupola\Base58;

/**
 * Some testing variables
 */

$message = "Signing this message confirms you are who you say you are. Please confirm this dialog to sign this message and authorize your login. Message number: 7bc87bcdf2";
$signature = "1f64bd92f912d97156e5caf95df0abff1f7faa8cea3590e9b94efedccb38e799d017233b7c1a65a430b67c2bd566b46f84c84396e3f36dee66b206806f12133673";
$address = "STM852gdYeYEK47KkHs55mMufgQejB1BMia15JmcDX2UTavP99RZz";

//$message = "This is not the signed message";

my_testing_header();

// calling my python script for testing
//iwb_sso_validate_signature($message,$address,$signature);

//testing3($message, $signature, $address);

//testing4($message, $signature, $address);

//testing5($message, $signature, $address);

//testing();

//testing2();

//my_verify_signature($message, $signature, $address);

iwb_sso_verify_message_signature($message, $signature, $address);

my_testing_footer();

/**
 * function iwb_sso_verify_message_signature ($message, $signature, $hivePublicKey)
 * Verify a signed message
 * 
 * @param   string  $message        the message that has been signed
 * @param   string  $signature      the signature
 * @param           $hivePublicKey  the public key of the signer 
 */
function iwb_sso_verify_message_signature ($message, $signature, $hivePublicKey) {

    // let's first instantinate a new EC Object from EC
    // We will use it as we go.
    $ec = new EC('secp256k1');

    color_red("Hive acquired public address: ");
    var_dump($hivePublicKey);

    // color_red("first 3 stripped: \n");
    $stripKey = substr($hivePublicKey, 3);
    // echo $stripKey;
    // echo "\n";

    color_red("base58 decoded key: ");
    $base58 = new Base58(["characters" => Base58::BITCOIN]);
    $decoded = $base58->decode($stripKey);
    $hexDecoded = bin2hex($decoded);
    var_dump($hexDecoded);
    echo "\n";

    if (substr($hexDecoded,0,2)== '04') {
        color_red("not compressed");
        return $hexDecoded;
    } elseif (substr($hexDecoded,0,2) == '02'|'03') {
        color_red("compressed, let's uncompress \n");
        $hexDecoded = substr($hexDecoded,0,66);
        $key = $ec->keyFromPublic($hexDecoded, 'hex');
        //print_r($key);
    }
 
    // let's hash the message - that is what is actually signed
    $msgHash = openssl_digest($message, 'SHA256' );

    // now lets extract 'r' and 's' from the signature into an array
    $sig   = [
        "r" => substr($signature, 2, 64),
        "s" => substr($signature, 66, 64)
    ];

    // I am manually setting the recovery parameter
    //$recovery_parameter = ord(hex2bin(substr($signature, 130, 2))) - 28;
    $recovery_parameter = 0;

    // // My attempt at a public key
    // $myX = 'a30563d5b3729cd092836810e4cace0dd579ea3ad884eb64cf9355bfb5d2298c';
    // $myY = 'bcf85deda475259de3a80b4e3fa9ca62b748bfb06488ee0b4432aeeaa3649a11';
    // $pub = '04'.$myX.$myY;
    // echo $pub;
    // echo "\n";
    

    // Get the public key from the signature
    $pubkey = $ec->recoverPubKey($msgHash, $sig, $recovery_parameter);

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


    // very the message signature key against the formatted public key pair
    echo "Verified: " . (($key->verify($msgHash, $sig) == TRUE) ? "true" : "false") . "\n";



}
/**
 * testing5()
 */
function testing5($message, $signature, $address) {
    
    //I need the public key to do this the way I am thinking:
    // how to get the expanded public key?

    /**
     * https://github.com/steemit/steem-python/blob/master/steembase/account.py
     * line 243
     * this is python
     */

    // def unCompressed(self):
    //     """ Derive uncompressed key """
    //     public_key = repr(self._pk)
    //     prefix = public_key[0:2]
    //     if prefix == "04":
    //         return public_key
    //     assert prefix == "02" or prefix == "03"
    //     x = int(public_key[2:], 16)
    //     y = self._derive_y_from_x(x, (prefix == "02"))
    //     key = '04' + '%064x' % x + '%064x' % y
    //     return key

    // def _derive_y_from_x(self, x, is_even):
    //     """ Derive y point from x point """
    //     curve = ecdsa.SECP256k1.curve
    //     # The curve equation over F_p is:
    //     #   y^2 = x^3 + ax + b
    //     a, b, p = curve.a(), curve.b(), curve.p()
    //     alpha = (pow(x, 3, p) + a * x + b) % p
    //     beta = ecdsa.numbertheory.square_root_mod_prime(alpha, p)
    //     if (beta % 2) == is_even:
    //         beta = p - beta
    //     return beta
    
    $msg = openssl_digest($message, 'SHA256' );

    $sig   = [
        "r" => substr($signature, 2, 64),
        "s" => substr($signature, 66, 64)
    ];

    //color_red("This is the sign r, and s: \n");
    //var_dump($sig);

    $ec = new EC('secp256k1');

        // Public key as '04 + x + y'
    //$pub = "049a1eedae838f2f8ad94597dc4368899ecc751342b464862da80c280d841875ab4607fb6ce14100e71dd7648dd6b417c7872a6ff1ff29195dabd99f15eff023e5";
    // echo $pub;
    // echo "\n";

    // My attempt at a public key
    $myX = 'a30563d5b3729cd092836810e4cace0dd579ea3ad884eb64cf9355bfb5d2298c';
    $myY = 'bcf85deda475259de3a80b4e3fa9ca62b748bfb06488ee0b4432aeeaa3649a11';
    $pub = '04'.$myX.$myY;
    echo $pub;
    echo "\n";

    // Calculating the public key
    $pubkey = $ec->recoverPubKey($hash, $sign, $recid);
    
    color_red("from recoverPubKey: x and y: \n");
    var_dump($pubkey);
    echo "\n";

    $key = $ec->keyFromPublic($pub, 'hex');

    echo "Verified: " . (($key->verify($msg, $sig) == TRUE) ? "true" : "false") . "\n";


}

/**
 * testing4()
 * From: 
 * https://packagist.org/packages/simplito/elliptic-php
 * 
 */
function testing4($message, $signature, $address) {

    $msg = 'ab4c3451';

    $ec = new EC('secp256k1');

    // Public key as '04 + x + y'
    $pub = "049a1eedae838f2f8ad94597dc4368899ecc751342b464862da80c280d841875ab4607fb6ce14100e71dd7648dd6b417c7872a6ff1ff29195dabd99f15eff023e5";

    // Signature MUST be either:
    // 1) hex-string of DER-encoded signature; or
    // 2) DER-encoded signature as byte array; or
    // 3) object with two hex-string properties (r and s)

    // case 1
    $sig = '30450220233f8bab3f5df09e3d02f45914b0b519d2c04d13ac6964495623806a015df1cd022100c0c279c989b79885b3cc0f117643317bc59414bfb581f38e03557b8532f06603';

    // case 2
    $sig = [48,69,2,32,35,63,139,171,63,93,240,158,61,2,244,89,20,176,181,25,210,192,77,19,172,105,100,73,86,35,128,106,1,93,241,205,2,33,0,192,194,121,201,137,183,152,133,179,204,15,17,118,67,49,123,197,148,20,191,181,129,243,142,3,85,123,133,50,240,102,3];

    // case 3
    $sig = ['r' => '233f8bab3f5df09e3d02f45914b0b519d2c04d13ac6964495623806a015df1cd', 's' => 'c0c279c989b79885b3cc0f117643317bc59414bfb581f38e03557b8532f06603'];

    // Import public key
    $key = $ec->keyFromPublic($pub, 'hex');

    // Verify signature

    echo "Verified: " . (($key->verify($msg, $sig) == TRUE) ? "true" : "false") . "\n";
}


/**
 * Testing 3
 * Hash the original message with sha256. Is there anything more to do with it?
 */

function testing3($message, $signature, $address) {

    color_red("Original address: ");
    var_dump($address);

    // color_red("first 3 stripped: \n");
    // $address = substr($address, 3);
    // var_dump($address);
    // echo "\n";


    // color_red("// Message sha256 hash: ");
    // $messageHash = openssl_digest($message, 'SHA256' );
    // echo "$messageHash \n";
    // echo "The hash is " . strlen($messageHash) . " bytes long.\n";
    // echo "\n";
    
    color_red("This is the signature: ");
    echo $signature;
    echo "\n";

    // color_red("What size is the signature? ");
    // $signatureLength = strlen($signature);
    // echo "The signature is " . $signatureLength . " bytes long.\n";
    // $signatureLength = $signatureLength/2;
    // echo "in half that's " . $signatureLength . " bytes long.\n";
    // $signatureLength = $signatureLength/2;
    // echo "half again is " . $signatureLength . " bytes long.\n";

    // color_red("convert from der??? : \n");
    // bin2hex($signature->toDer());

    // color_red("base64 decoded signature: ");
    // $decoded = base64_decode($signature);
    // echo $decoded;
    // var_dump($decoded);
    // echo "\n";

    // color_red("base58 decoded signature: ");
    // $base58 = new Base58(["characters" => Base58::BITCOIN]);
    // $decoded = $base58->decode($signature);
    // var_dump($decoded);
    // echo "\n";

    // color_red("what am I doing here? : \n");
    // $hex = hex2bin("6578616d706c65206865782064617461");
    // var_dump($hex);
    // echo "\n";

    // color_red("what am I doing here? : \n");
    // $binFromHex = hex2bin($signature);
    // var_dump($binFromHex);
    // echo "\n";

    // color_red("Can I strip the first byte? : \n");
    // $binFromHex = substr($binFromHex, 1);
    // var_dump($binFromHex);
    // //$signature = $binFromHex;

    $hash = openssl_digest($message, 'SHA256' );

    $sign   = [
        "r" => substr($signature, 2, 64),
        "s" => substr($signature, 66, 64)
    ];
    color_red("This is the sign r, and s: \n");
    var_dump($sign);

    // WHat's going on here?
    $recid  = ord(hex2bin(substr($signature, 130, 2))) - 27;
    // var_dump($recid);
    // This 'works' by setting it to either 0, or 1, but
    // I'm not sure this is correct, or even proper...
    // I'm not understanding what's actually happening here yet.
    $recid = 0;
    if ($recid != ($recid & 1)){
        echo "no dice here\n";
        // return;
    }

        // the 27 is arbitrary?
    // https://medium.com/mycrypto/the-magic-of-digital-signatures-on-ethereum-98fe184dc9c7
    //recover_parameter = bytearray(signature)[0] - 4 - 27  # recover parameter
    /**
     * Ok... if I am reading this correcly, the thing above... this is 
     * mostly an 'eth' thing...
     * Hive is not based on 'eth', it's graphene... which is more
     * like bitcoin that it is like eth.
     * So... I should just be able to get the public key
     * and then have to just figure out what format it needs to be
     * in to make it 'appear' correct - like the original key.
     */


    $ec = new EC('secp256k1');
    $pubkey = $ec->recoverPubKey($hash, $sign, $recid);
    
    color_red("from recoverPubKey: x and y: \n");
    var_dump($pubkey);
    echo "\n";

    /**
     * Ok, so let's create the compressed public key and see how it compaires.
     * 
     * There is an example from graphene on my tablet in brave:
     * 
     * do that here... it's something like x and y combined and then compressed
     * in some form ascii??
     */

    /**
      * I belvie this is being doen here in python from here:
      * https://github.com/steemit/steem-python/blob/master/steembase/account.py 
      *  def derivesha256address(self):
      *  """ Derive address using ``RIPEMD160(SHA256(x))`` """
      *  pkbin = unhexlify(repr(self._pubkey))
      *  addressbin = ripemd160(hexlify(hashlib.sha256(pkbin).digest()))
      *  return Base58(hexlify(addressbin).decode('ascii'))
    */

    color_red("base58 encoded x: ");
    $base58 = new Base58(["characters" => Base58::BITCOIN]);
    $myX = "bcf85deda475259de3a80b4e3fa9ca62b748bfb06488ee0b4432aeeaa3649a11";
    $myX = "e47e1e2acbb0ee103fd1f3aa6dedee8f8f6e9017";
    $encoded = $base58->encode($myX);
    var_dump($encoded);
    echo "\n";

    // $getX = extract($pubkey->getX());
    // var_dump($getX);

    //var_dump($pubkey->x);
    // print_r($pubkey->x);
    // echo "\n";


    // $class_methods = get_class_methods($pubkey);
    // // or
    // //$class_methods = get_class_methods(new myclass());
    // foreach ($class_methods as $method_name) {
    //     echo "$method_name\n";
    // }

    color_red("Generated Public Key address: \n");    
    $genAddress = "Nothing yet";
    //$genAddress = get_object_vars($pubkey);

    //$address = $ec;
    //$address = "STM" . substr(Keccak::hash(substr(hex2bin($pubkey->encode("hex")), 1), 256), 24);
    var_dump($genAddress);




    // color_red("base58 encoded x: ");
    // $base58 = new Base58(["characters" => Base58::BITCOIN]);
    // $decoded = $base58->decode($address);
    // var_dump($decoded);
    // echo "\n";



    //$binSignature =unpack('g', $signature);
    //$binSignature = hexStringToByteString($signature);
    //$binSignature = hex2String($signature);
    //$binSignature = hexdec($signature);

    echo "\n";

    //iwb_sso_validate_signature($message,$address,$signature);

    // testing results

    /**
     * 
     * 
     * 
     */

    
//    $bitcoinB58 = new Base58(["characters" => Base58::BITCOIN]);
 //   $decoded = $bitcoinB58->decode($signature);
 //   color_red("baseb8 decoded signature: $decoded \n");
    //color_red("baseb8 decoded signature: $decoded \n");
    //echo "" . strlen($decoded) . " bytes long.\n";
    //echo "The baseb8 decoded signature is " . strlen($decoded) . " bytes long.\n";


    // color_red("The signature in hex: ");
    // $hexSignature = bin2hex($signature);
    // echo $hexSignature;
    // echo "\n";
    // color_red("The signature in hex is: ");
    // echo  strlen($hexSignature) . " bytes long.\n";



}



function iwb_sso_validate_signature($message,$publicKey,$signature) {
    // Python script for signature validation
    $iwb_sso_PyScript = './iwbpy.py';
    
    $shellCommandArgs = '"'. $message. '" "'. $publicKey. '" "'. $signature. '"';
    $shellCommand = $iwb_sso_PyScript;

    $output = shell_exec($shellCommand. ' '. $shellCommandArgs);
    echo $output;
    return $output;
}

/**
 * Testing if the openssl hash is the same?
 * It is!
 */
function testing2() {
    color_red("\nHashing test message SHA256: ");
    $testmessage = 'Nobody inspects the spammish repetition';
    // Lets hash our message using opensll's digest
    $hash = openssl_digest($testmessage, 'SHA256' );
    echo $hash;

}

/**
 * This is my testing function
 */
function testing() {
    /**
     * Some testing variables
     */
    $message = "Signing this message confirms you are who you say you are. Please confirm this dialog to sign this message and authorize your login. Message number: 7bc87bcdf2";
    $signature = "1f64bd92f912d97156e5caf95df0abff1f7faa8cea3590e9b94efedccb38e799d017233b7c1a65a430b67c2bd566b46f84c84396e3f36dee66b206806f12133673";
    $address = "STM852gdYeYEK47KkHs55mMufgQejB1BMia15JmcDX2UTavP99RZz";

    /**
     * Note: this is the base58 alphabet for steem/hive (I am pretty sure this is hive too)
     * BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
     * this is the same as the 'bitcoin' alphabet.
     * 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
     * https://github.com/steemit/steem-python/blob/master/steembase/base58.py
     * line 114
     * another persons fork??
     * https://github.com/tochev/python3-cryptocoins/raw/master/cryptocoins/base58.py
     */

    /**
     * Setting up my enviornment to run with some debug information
     */
    system('clear');
    echo "\e[0;31mMerry Christmas!\e[0m";
    echo "   begin*************\n";

    /**
     * 
     */
    $bitcoinB58 = new Base58(["characters" => Base58::BITCOIN]);

    $encoded = $bitcoinB58->encode('The quick brown fox jumps over the lazy dog.');
    color_red("\nbase58 - bitcoin - Encoded: ");
    echo $encoded;

    color_red("\nbase58 - bitcoin - Decoded: ");
    $decoded = $bitcoinB58->decode($encoded);
    echo $decoded;

    color_red("\nbase58 - bitcoin - Decoded: ");
    $decoded = $bitcoinB58->decode('USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z');
    echo $decoded;

    echo "\n";
    color_red("\nOriginal String: ");
    echo $message;

    color_red("\nbase58 encoded: ");
    $encoded = $bitcoinB58->encode($message);
    echo $encoded;

    $decoded = $bitcoinB58->decode($encoded);
    color_red("\nbase58 decoded: ");
    echo $decoded;

    // color_red("String to hex: ");
    // $message_hex = string2Hex($message);
    // echo $message_hex;
    // echo "\n";

    // echo "openssl digest String: ";
    // $opensslhash = openssl_digest($message, 'SHA256');
    // echo $opensslhash;
    // echo "\n\n";

    // color_red("hex 2 bin: ");
    // $message_bin = hex2bin($message_hex);
    // var_dump($message_bin);
    // //echo $message_bin;
    // echo "\n";

    // echo "keccak digest  String: ";
    // $msglen = strlen($message);
    // $hash   = Keccak::hash($message, 256);
    // // $hash   = Keccak::hash("{$msglen}{$message}", 256);
    // echo $hash;
    // echo "\n\n";

    //(below is python code) not sure if those are the right numbers for recover_parameter?
    //echo "nothing yet: \n";
    //$recover_parameter =  bytearray(signature)[0] - 4 - 27;  # recover parameter only
    //$message = openssl_digest($message, 'SHA256');
    //echo $message;
    //echo "\n\n";

    color_red("\nString to hex: ");
    $message = string2Hex($message);
    echo $message;

    color_red("\nHex to string: ");
    $message = hex2String($message);
    echo $message;

    //echo "string2Byte array: ";
    $message = (string2ByteArray($message));

    color_red("\nByte array to hex: ");
    $message = byteArray2Hex($message);
    print_r($message);

    color_red("\nHex to string: ");
    $message = hex2String($message);
    echo $message;

    // color_red("\nUnhexed Signature: ");    
    // $unhexed_signature = hex2bin($signature);
    // var_dump($unhexed_signature);
    // echo "\n";
    // var_dump(bin2hex($unhexed_signature));
    // echo "\n";

    color_red("\n******END\n");

    exit;

}


function verify_signature($message, $signature, $address) {
    $msglen = strlen($message);
    $hash   = Keccak::hash("\x19Ethereum Signed Message:\n{$msglen}{$message}", 256);
    $sign   = ["r" => substr($signature, 2, 64),
              "s" => substr($signature, 66, 64)];
    $recid  = ord(hex2bin(substr($signature, 130, 2))) - 27;
    if ($recid != ($recid & 1)){
      return 0;
    }

    $ec = new EC('secp256k1');
    $pubkey = $ec->recoverPubKey($hash, $sign, $recid);
  
    return $address == $this->pub_key_to_address($pubkey);
  }


function my_verify_signature($message, $signature, $address) {

    // $msglen = strlen($message);

    // I'm using a different hash I think? I don't know what
    // Hive Keychain is using?
    // hashfn=hashlib.sha256
    // from: /usr/local/lib/python3.9/site-packages/beemgraphenebase/ecdsasig.py
    // line 263
    // Hasing the message using SHA256
    // I beleive that's what is actually signed.
    $hash = openssl_digest($message, 'SHA256' );
    //$hash   = Keccak::hash("{$msglen}{$message}", 256);

    /**
     * the signature... I'm not sure, but I think it's base58 encoded
     * so let's decode it first
     */
    $base58 = new Base58(["characters" => Base58::BITCOIN]);

    //$sig = hex2bin($signature);
    color_red('Signature? ');
    echo $sig;
    echo "\n";

    color_red('Did we geet here?');

    $sig = $base58->decode($sig);

    


    

    // // Still don't understand this yet.
    // $sign   = ["r" => substr($signature, 2, 64),
    //           "s" => substr($signature, 66, 64)];

    // echo "sign r: " . $sign['r'];
    // echo "\n";
    // echo "sign s: " . $sign['s'];
    // echo "\n";

    $recid  = ord(hex2bin(substr($signature, 130, 2))) - 27;

    echo "recid: " . $recid;
    echo "\n";

    if ($recid != ($recid & 1)){
        color_red('HERE');
        return 0;
    }
    // Signature MUST be either:
    // 1) hex-string of DER-encoded signature; or
    // 2) DER-encoded signature as byte array; or
    // 3) object with two hex-string properties (r and s)

    // case 1
    //$sign = '30450220233f8bab3f5df09e3d02f45914b0b519d2c04d13ac6964495623806a015df1cd022100c0c279c989b79885b3cc0f117643317bc59414bfb581f38e03557b8532f06603';

    // case 2
    // $sig = [48,69,2,32,35,63,139,171,63,93,240,158,61,2,244,89,20,176,181,25,210,192,77,19,172,105,100,73,86,35,128,106,1,93,241,205,2,33,0,192,194,121,201,137,183,152,133,179,204,15,17,118,67,49,123,197,148,20,191,181,129,243,142,3,85,123,133,50,240,102,3];

    // case 3
    // $sig = ['r' => '233f8bab3f5df09e3d02f45914b0b519d2c04d13ac6964495623806a015df1cd', 's' => 'c0c279c989b79885b3cc0f117643317bc59414bfb581f38e03557b8532f06603'];

    $ec = new EC('secp256k1');
    $pubkey = $ec->recoverPubKey($hash, $sign, $recid);

    color_red("\nDerived Public Key: stm");
    echo $pubkey;

    color_red("\n******END\n");

    exit;

    // what is this?
    $recid  = ord(hex2bin(substr($signature, 130, 2))) - 27;
    // What are the parameters for r, and for s?
    $sign   = [
        "r" => substr($signature, 2, 64),
        "s" => substr($signature, 66, 64)
    ];

    echo $msglen;
    echo "\n";
    echo "hash: " . $hash;
    echo "\n";
    echo "sign r: " . $sign['r'];
    echo "\n";
    echo "sign s: " . $sign['s'];
    echo "\n";
        
    $recid  = ord(hex2bin(substr($signature, 130, 2))) - 27;
    
    echo "recid: " . $recid;
    echo "\n";
    
    if ($recid != ($recid & 1)){
        //return 0;
        echo "HERE\n";
    }

    $ec = new EC('secp256k1');
    $pubkey = $ec->recoverPubKey($hash, $sign, $recid);
    
    echo "pubkey: " . $pubkey;

//    return $address == $this->pub_key_to_address($pubkey);
}


/**
 * My color notation function for fun
 */
function color_red($echo_text) {
    echo "\e[0;31m$echo_text\e[0m";
}

/**
 * https://gist.github.com/miguelmota/8f235b9dfd1ff1dda1d63c1df77a861e
 * PHP byte array to hex, hex to byte array, string to hex, hex to string utility functions
 * 
 */

function string2ByteArray($string) {
    return unpack('C*', $string);
  }
  
  function byteArray2String($byteArray) {
    $chars = array_map("chr", $byteArray);
    return join($chars);
  }
  
  function byteArray2Hex($byteArray) {
    $chars = array_map("chr", $byteArray);
    $bin = join($chars);
    return bin2hex($bin);
  }
  
  function hex2ByteArray($hexString) {
    $string = hex2bin($hexString);
    return unpack('C*', $string);
  }
  
  function string2Hex($string) {
    return bin2hex($string);
  }
  
  function hex2String($hexString) {
    return hex2bin($hexString);
  }


function hexStringToByteString($hexString){
    $len=strlen($hexString);

    $byteString="";
    for ($i=0;$i<$len;$i=$i+2){
        $charnum=hexdec(substr($hexString,$i,2));
        $byteString.=chr($charnum);
    }

return $byteString;
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


function pub_key_to_address($pubkey) {
    return "0x" . substr(Keccak::hash(substr(hex2bin($pubkey->encode("hex")), 1), 256), 24);
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

?>
