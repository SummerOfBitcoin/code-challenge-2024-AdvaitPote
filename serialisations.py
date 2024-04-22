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
import bech32
import binascii

def bech_32(data):
    spk = binascii.unhexlify(data)
    version = spk[0] - 0x50 if spk[0] else 0
    program = spk[2:]
    return bech32.encode('bc', version, program)

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
        else:
            transaction += compact_size(0).hex()
        index += 1
    transaction += data['locktime'].to_bytes(4, byteorder='little').hex()        
    serialize_review += data['locktime'].to_bytes(4, byteorder='little').hex()        
    return (transaction, serialize_review)

def tx_weight(data):
    weight = len(serialize(data)[0])*4 - 3*(4) # version and marker to be subtracted
    witness_script_len = 0
    for input in data['vin']:
        if 'witness'in input:
            witness_script_len += len(compact_size(len(input['witness'])).hex())
            for witness in input['witness']:
                witness_script_len += len(compact_size(int(len(witness)/2)).hex())
                witness_script_len += len(witness)
    weight -= 3*witness_script_len
    return int(weight/2)

def preimage(data, i, is_p2wsh=False):
    input = data['vin'][i]
    transaction = serialize(data)[0]
    version = transaction[:8] #
    txvouts = ""
    seqs = ""
    for j in range(len(data['vin'])):
        txid = bytes.fromhex(data['vin'][j]['txid'])[::-1].hex()
        vout = data['vin'][j]['vout'].to_bytes(4, byteorder='little').hex()
        sequence = data['vin'][j]['sequence'].to_bytes(4, byteorder='little').hex()
        txvouts += txid
        txvouts += vout
        seqs += sequence
    seqs = sha256(sha256(bytes.fromhex(seqs)).digest()).digest().hex()
    # print(txvouts)
    # seqs = sha256(sha256(bytes.fromhex(seqs)).digest()).digest().hex()
    hash_inputs = sha256(sha256(bytes.fromhex(txvouts)).digest()).digest().hex() #
    inputs = bytes.fromhex(input['txid'])[::-1].hex() +input['vout'].to_bytes(4, byteorder='little').hex() #
    pkhash = input['prevout']['scriptpubkey_asm'].split(" ")[2]
    if is_p2wsh:
        scriptcode = compact_size(int(len(input['witness'][-1])/2)).hex() + input['witness'][-1]
    else:
        scriptcode = "1976a914" + pkhash + "88ac" #
    amount = input['prevout']['value'].to_bytes(8, byteorder='little').hex()      #
    sequence = input['sequence'].to_bytes(4, byteorder='little').hex() #
    outputs  = ""
    for output in data['vout']:
        value = output['value'].to_bytes(8, byteorder='little').hex()      
        size = compact_size(int(len(output['scriptpubkey'])/2)).hex()
        outputs += (value + size + output['scriptpubkey'])
    # print(outputs)
    hash_outputs = sha256(sha256(bytes.fromhex(outputs)).digest()).digest().hex() #
    locktime = data['locktime'].to_bytes(4, byteorder='little').hex()        #
    return (version + hash_inputs + seqs + inputs + scriptcode + amount + sequence + hash_outputs + locktime + input['witness'][0][-2:] + "000000")