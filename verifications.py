import os
import sys
import json
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import hashlib
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
import ecdsa
from hashlib import sha256
import base58
import os
import struct
import json
from hashlib import sha256
from serialisations import serialize, hash160, decode_sig, preimage, bech_32

def verify_multisig(data, i, is_p2wsh=True):
    input = data['vin'][i]
    inner_script = input['inner_witnessscript_asm'].split(" ")
    witness = input['witness']
    signatures = witness[1:-1]
    inner_script.pop()
    pks = int(inner_script[-1][-1])
    public_keys = []
    inner_script.pop()
    for j in range(pks):
        public_key = inner_script.pop()
        inner_script.pop()
        public_keys.append(public_key)
    public_keys = public_keys[::-1]
    matched_sigs = 0
    for sig in signatures:
        if is_p2wsh:
            # print((data, i))
            message = sha256(bytes.fromhex(preimage(data, i, is_p2wsh))).digest().hex()  
        # else:

        decoded_signature = decode_sig(sig[:-2])

        for pbkey in public_keys:
            verifying_key = VerifyingKey.from_string(bytes.fromhex(pbkey), curve=SECP256k1)
            try:
                verifying_key.verify(bytes.fromhex(decoded_signature), bytes.fromhex(message), hashfunc=sha256)
                matched_sigs += 1
                break
            except:
                continue
    return matched_sigs == len(signatures)

def verify_p2pkh(data, i):
    input = data['vin'][i]
    modified_transaction = serialize(data)[0]
    # print(modified_transaction)
    scriptsig = hex(int(len(input['scriptsig'])/2))[2:] + input['scriptsig']
    scriptpubkey = hex(int(len(input['prevout']['scriptpubkey'])/2))[2:] + input['prevout']['scriptpubkey']
    pub_key = bytes.fromhex(input['scriptsig_asm'].split(" ")[3])
    pkhash = input['prevout']['scriptpubkey_asm'].split(" ")[3]
    for k in range(len(data['vin'])):
        scriptsig_replace =  hex(int(len(data['vin'][k]['scriptsig'])/2))[2:] + data['vin'][k]['scriptsig']
        sig = decode_sig(str(input['scriptsig_asm'].split(" ")[1][:-2]))
        if k == i:
            modified_transaction = modified_transaction.replace(scriptsig, scriptpubkey)
        else:
            if input['scriptsig_asm'].split(" ")[1][-2:] == "81":
                modified_transaction = modified_transaction.replace(scriptsig_replace, "")
            else:
                modified_transaction = modified_transaction.replace(scriptsig_replace, "00")
    modified_transaction += input['scriptsig_asm'].split(" ")[1][-2:] + "0"*6
    # print(data)
    # print(sig)
    # print(pub_key.hex())
    message = sha256(bytes.fromhex(modified_transaction)).digest()
    # print(message.hex())
    # print(" ")
    vk = VerifyingKey.from_string(pub_key, curve=ecdsa.SECP256k1)
    if hash160(pub_key).hex() != pkhash:
        return False
    try:
        result = vk.verify(bytes.fromhex(sig), message, hashfunc=sha256)
    except BadSignatureError:
        return False
    address = "00" + pkhash + sha256(sha256(bytes.fromhex("00" + pkhash)).digest()).digest().hex()[:8] 
    if base58.b58encode(bytes.fromhex(address)).decode('utf-8') != input['prevout']['scriptpubkey_address']:
        return False
    return True

def verify_p2sh(data, i):
    input = data['vin'][i]
    redeem = input['inner_redeemscript_asm']
    data_new = {}

    if hash160(bytes.fromhex(input['scriptsig_asm'].split(" ")[-1])).hex() != input['prevout']['scriptpubkey_asm'].split(" ")[-2]:
        return False
    
    # if input['inner_redeemscript_asm'].split(" ")[-1] == "OP_CHECKMULTISIG": 
    #     data_new = data
    #     verify_multisig(data, i, is_p2wsh=False)

    elif input['inner_redeemscript_asm'].split(" ")[1] == "OP_PUSHBYTES_32":
        data_new = data
        data_new['vin'][i]['prevout']['scriptpubkey_asm'] = redeem
        return verify_p2wsh(data_new, i)
    
    elif input['inner_redeemscript_asm'].split(" ")[1] == "OP_PUSHBYTES_20":
        data_new = data
        data_new['vin'][i]['prevout']['scriptpubkey_asm'] = redeem
        return verify_p2wpkh(data_new, i)

    return True

def verify_p2wpkh(data, i):
    input = data['vin'][i]
    modified_transaction = serialize(data)[0]
    pub_key = bytes.fromhex(input['witness'][1])
    pkhash = input['prevout']['scriptpubkey_asm'].split(" ")[2]
    sig = decode_sig(str(input['witness'][0][:-2]))
    modified_transaction = preimage(data, i)
    message = sha256(bytes.fromhex(modified_transaction)).digest()
    # print(modified_transaction)
    vk = VerifyingKey.from_string(pub_key, curve=ecdsa.SECP256k1)
    if hash160(pub_key).hex() != pkhash:
        return False
    try:
        result = vk.verify(bytes.fromhex(sig), message, hashfunc=sha256)
    except BadSignatureError:
        return False
    # if bech_32(input['prevout']['scriptpubkey']) != input['prevout']['scriptpubkey_address']:
    #     return False
    return True

def verify_p2wsh(data, i):
    input = data['vin'][i]
    witnesses = input['witness']

    if sha256(bytes.fromhex(witnesses[-1])).digest().hex() != input['prevout']['scriptpubkey_asm'].split(" ")[2]:
        return False
    
    inner_script = input['inner_witnessscript_asm']
    if inner_script.split(" ")[-1] == "OP_CHECKMULTISIG":
        # print(i)
        if not verify_multisig(data, i):
            return False
    # if bech_32(input['prevout']['scriptpubkey']) != input['prevout']['scriptpubkey_address']:
    #     return False
    return True