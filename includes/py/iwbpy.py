#!/usr/bin/python3

###
# iwbpy.py
# ** please note ** - this is a work in progress, see : https://www.innerwebblueprint.com/blog/innerweb-monolog/a-work-in-progress-learning-to-iterate/
#
# This script verifies the signature of a signed message using the beempy
# python lbirary. It is a derivation of a script posted on 'the Hive' by
# @brianoflondon. Thank you @brianoflondon, you saved me hours and hours!
# https://www.innerwebblueprint.com/go/code-thank-you/
# 
# Also note, this is a work-around, as I want/wanted to do this natively in PHP specifically so that 
# any WordPress install can use this plugin. 
# Most hosts will not have the beempy python library installed.
# For now though, if using my IWB Website Factory Docker image, this works well.
# ###

import os
import sys
from beemgraphenebase.account import PublicKey
from beemgraphenebase.ecdsasig import verify_message
from binascii import hexlify, unhexlify
from beem.account import Account

# asigning required command line arguments
try:
    iwbMessage = str(sys.argv[1]);
    #print(iwbMessage);
except IndexError:
    result = 'no message provided';
    print(result); 
    sys.exit(1)

try:
    iwbPublicKey = str(sys.argv[2]);
    #print(iwbPublicKey);
except IndexError:
    result = 'no publickey provided';
    print(result);
    sys.exit(1)

try:
    iwbHiveSignature = str(sys.argv[3]);
    #print(iwbHiveSignature);
except IndexError:
    result = 'no signature provided';
    print(result);
    sys.exit(1)

pubkey = PublicKey(iwbPublicKey)
enc_msg = iwbMessage
signature = iwbHiveSignature

msgkey = verify_message(enc_msg, unhexlify(signature))
pk = PublicKey(hexlify(msgkey).decode("ascii"))
if str(pk) == str(pubkey):
    print("SUCCESS: signature matches pubkey")
    # acc = Account(acc_name)
    # match = False
    # for key in acc['posting']['key_auths']:
    #     match = match or ans['publicKey'] in key
    # if match:
    #     print('Matches public key from Hive')
    sys.exit(0)
else:
    print(enc_msg)
    print("ERROR: message was signed with a different key")
    sys.exit(1)
