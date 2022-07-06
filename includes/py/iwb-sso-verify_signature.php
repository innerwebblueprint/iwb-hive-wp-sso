<?php

require_once ('includes/lib/Keccak/Keccak.php');
require_once ('includes/lib/Elliptic/EC.php');
require_once ('includes/lib/Elliptic/Curves.php');

use Elliptic\EC;
use kornrunner\Keccak;

function pub_key_to_address($pubkey) {
    return "0x" . substr(Keccak::hash(substr(hex2bin($pubkey->encode("hex")), 1), 256), 24);
  }

function verify_signature($message, $signature, $address) {
    $msglen = strlen($message);
    $hash   = Keccak::hash("\x19Ethereum Signed Message:\n{$msglen}{$message}", 256);
    $sign   = [
        "r" => substr($signature, 2, 64),
        "s" => substr($signature, 66, 64)
    ];
    
    $recid  = ord(hex2bin(substr($signature, 130, 2))) - 27;
    if ($recid != ($recid & 1)){
        return 0;
    }

    $ec = new EC('secp256k1');
    $pubkey = $ec->recoverPubKey($hash, $sign, $recid);

    return $address == $this->pub_key_to_address($pubkey);
}



?>