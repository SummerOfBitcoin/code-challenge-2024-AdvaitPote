from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
import ecdsa
from hashlib import sha256

import os
import json
from hashlib import sha256
from serialisations import serialize

def compact_size(value):
    if value < 0xfd:
        return bytes([value])
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')
    
# def serialize(data):
#     # print(data)
#     transaction = "0" + str(data['version']) + "0"*6
#     witnesses = [False]*len(data['vin'])
#     index = 0
#     for input in data['vin']:
#         if 'witness' in input:
#             witnesses[index] = True
#         index += 1
#     if True in witnesses:
#         transaction += "0001"
#     transaction += compact_size(len(data['vin'])).hex()
#     for input in data['vin']:
#         txid = bytearray.fromhex(input['txid'])[::-1].hex()
#         vout = input['vout'].to_bytes(4, byteorder='little').hex()        
#         scriptsigsize = compact_size(int(len(input['scriptsig'])/2)).hex()
#         scriptsig = input['scriptsig']
#         sequence = input['sequence'].to_bytes(4, byteorder='little').hex()
#         transaction += "".join([txid, vout, scriptsigsize, scriptsig, sequence])
#     transaction += compact_size(len(data['vout'])).hex()
#     for output in data['vout']:
#         amount = output['value'].to_bytes(8, byteorder='little').hex()        
#         scriptpubkeysize = compact_size(int(len(output['scriptpubkey'])/2)).hex()
#         scriptpubkey = output['scriptpubkey']
#         transaction += "".join([amount, scriptpubkeysize, scriptpubkey])
#     serialize_review = transaction
#     if True in witnesses:
#         serialize_review = serialize_review[:8] + serialize_review[12:]
#     index = 0
#     for input in data['vin']:
#         if witnesses[index]:
#             transaction += compact_size(len(input['witness'])).hex()
#             for witness in input['witness']:
#                 wit_len = compact_size(int(len(witness)/2)).hex()
#                 transaction += "".join([wit_len, witness])
#         index += 1
#     transaction += data['locktime'].to_bytes(4, byteorder='little').hex()        
#     serialize_review += data['locktime'].to_bytes(4, byteorder='little').hex()        
#     return (transaction, serialize_review)

# Generate a private key

# Derive the corresponding public key
public_key = bytes.fromhex("02ea7ba456f44065674e75e7873115ec0779dbbfdd1a28bc421ac369c8a91d446b")

# Message to be signed
file_name = "ff5975493132aed7718939a60f930456cbca87fb673f5da25f70b464cf199ea6.json"
# file_name = files[i]

    # print(file_name)
with open('mempool/' + file_name, 'r') as file:
    try:
        data = json.load(file)
        transaction, serialize_review = serialize(data)
        if transaction == serialize_review:
            print("yes")
        # print(transaction)
        # print(transaction)
        # print(serialize_review)
        transaction_id = sha256(sha256(bytes.fromhex(serialize_review)).digest()).digest().hex()
        hashed_id = sha256(bytes.fromhex(transaction_id)[::-1]).digest().hex()
        print(hashed_id)
        if hashed_id != file_name[:-5]:
            print("No")
            print(file_name)
        # else:
            # print(transaction)
            # print(serialize_review)
            # print(serialize_review == transaction)
            # print(hashed_id)
        input_sum = 0
        output_sum = 0
        for input in data['vin']:
            input_sum += input['prevout']['value']
        for output in data['vout']:
            output_sum += output['value']
        print(input_sum)
        print(output_sum)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in file {file}: {e}")

print(transaction)
# transaction = "01000000012c9823d2302bccf67597c38c6f32200dd44acc4d3226293bffc94db8d76303e3000000001976a914070fd7f673a6b8e0bf617f79201566a6655da67b88acfdffffff01804c2e0000000000160014d72c0b982cc903ef022131ea7b0177f22f700e5e0000000001000000"

# transaction = "0100000001a4e61ed60e66af9f7ca4f2eb25234f6e32e0cb8f6099db21a2462c42de61640b010000006b483045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1037952ce26e91e02205aa5f8f88f29bb4ad5808ebc12abfd26bd791256f367b04c6d955f01f28a7724012103f0609c81a45f8cab67fc2d050c21b1acd3d37c7acfd54041be6601ab4cef4f31feffffff02f9243751130000001976a9140c443537e6e31f06e6edb2d4bb80f8481e2831ac88ac14206c00000000001976a914d807ded709af8893f02cdc30a37994429fa248ca88ac751a060001"


message = sha256(bytes.fromhex(transaction)).digest()
# message = bytes.fromhex(transaction + "01")
# message = b"Hello, this is a test message"

# print(message.hex())
signature = bytes.fromhex("c792a465752f356ca187dc113552f6f32cc3b1499e0b16aa8bb4ab9799d237db10733df96dafa890b039c3e4533879277024399795276e974d297e6b3352c861")

vk = VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)

try:
    # Verify the signature
    result = vk.verify(signature, message, hashfunc=sha256)
    print("Signature is valid.")
except BadSignatureError:
    print("Signature is invalid.")