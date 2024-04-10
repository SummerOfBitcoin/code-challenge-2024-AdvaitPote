import os
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
import json
from hashlib import sha256

def hash160(data):
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash

def decode_sig(der_signature_bytes):
    der_signature_bytes = bytes.fromhex(der_signature_bytes)
    r, s = decode_dss_signature(der_signature_bytes)
    r = hex(r)[2:]  
    s = hex(s)[2:]
    r = "0"*(64-len(r)) + r
    s = "0"*(64-len(s)) + s
    return (r+s)

def compact_size(value):
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')
    
def serialize(data):
    transaction = "0" + str(data['version']) + "0"*6
    witnesses = [False]*len(data['vin'])
    index = 0
    for input in data['vin']:
        if 'witness' in input:
            witnesses[index] = True
        index += 1
    if True in witnesses:
        transaction += "0001"
    transaction += compact_size(len(data['vin'])).hex()
    for input in data['vin']:
        txid = bytearray.fromhex(input['txid'])[::-1].hex()
        vout = input['vout'].to_bytes(4, byteorder='little').hex()        
        scriptsigsize = compact_size(int(len(input['scriptsig'])/2)).hex()
        scriptsig = input['scriptsig']
        sequence = input['sequence'].to_bytes(4, byteorder='little').hex()
        transaction += "".join([txid, vout, scriptsigsize, scriptsig, sequence])
    transaction += compact_size(len(data['vout'])).hex()
    for output in data['vout']:
        amount = output['value'].to_bytes(8, byteorder='little').hex()        
        scriptpubkeysize = compact_size(int(len(output['scriptpubkey'])/2)).hex()
        scriptpubkey = output['scriptpubkey']
        transaction += "".join([amount, scriptpubkeysize, scriptpubkey])
    serialize_review = transaction
    if True in witnesses:
        serialize_review = serialize_review[:8] + serialize_review[12:]
    index = 0
    for input in data['vin']:
        if witnesses[index]:
            transaction += compact_size(len(input['witness'])).hex()
            for witness in input['witness']:
                wit_len = compact_size(int(len(witness)/2)).hex()
                transaction += "".join([wit_len, witness])
        index += 1
    transaction += data['locktime'].to_bytes(4, byteorder='little').hex()        
    serialize_review += data['locktime'].to_bytes(4, byteorder='little').hex()        
    return (transaction, serialize_review)