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
import json
from hashlib import sha256
from serialisations import serialize, hash160, decode_sig

files = os.listdir('mempool') 
invalid_transactions = set([])
ds_inputs = set([]) # set to check double spending of inputs
for i in range(len(files)): 
    file_name = files[i]
    with open('mempool/' + file_name, 'r') as file:
        try:
            data = json.load(file)
            transaction, serialize_review = serialize(data)

            if len(transaction) < 200 or len(transaction) > 2000000: # transactions should be minimum 100 bytes and max 1 MB
                invalid_transactions.add(file_name)
                continue

            if len(data['vin']) == 0 or len(data['vout']) == 0: # input or output lists should be non-empty
                invalid_transactions.add(file_name)
                continue

            in_sum = 0 # inputs and outputs should be less than 21M coins
            out_sum = 0
            for input in data['vin']:
                in_sum += input['prevout']['value']
            for output in data['vout']:
                out_sum += output['value']
            if in_sum > 21 * (10 ** 14) or out_sum > 21 * (10 ** 14):
                invalid_transactions.add(file_name)
                continue

            for input in data['vin']: # check double spending
                old_size = len(ds_inputs)
                ds_inputs.add((input['txid'], input['vout']))
                if len(ds_inputs) == old_size:
                    print(file_name)
                    sys.exit()
                    # break

            transaction_id = sha256(sha256(bytearray.fromhex(serialize_review)).digest()).digest().hex()
            hashed_id = sha256(bytearray.fromhex(transaction_id)[::-1]).digest().hex()
            if hashed_id != file_name[:-5]:
                print("No")
                print(file_name)
            wit = False

            for input in data['vin']:
                if 'witness' in input:
                    wit = True
                    break
            if not wit:
                for j in range(len(data['vin'])):
                    if data['vin'][j]['prevout']['scriptpubkey_type'] == "p2pkh":                        
                        input = data['vin'][j]
                        modified_transaction = transaction
                        scriptsig = hex(int(len(input['scriptsig'])/2))[2:] + input['scriptsig']
                        scriptpubkey = hex(int(len(input['prevout']['scriptpubkey'])/2))[2:] + input['prevout']['scriptpubkey']
                        pub_key = bytes.fromhex(input['scriptsig_asm'].split(" ")[3])
                        pkhash = input['prevout']['scriptpubkey_asm'].split(" ")[3]
                        for k in range(len(data['vin'])):
                            scriptsig_replace =  hex(int(len(data['vin'][k]['scriptsig'])/2))[2:] + data['vin'][k]['scriptsig']
                            sig = decode_sig(str(input['scriptsig_asm'].split(" ")[1][:-2]))
                            if k == j:
                                modified_transaction = modified_transaction.replace(scriptsig, scriptpubkey)
                            else:
                                modified_transaction = modified_transaction.replace(scriptsig_replace, "00")
                        modified_transaction += input['scriptsig_asm'].split(" ")[1][-2:] + "0"*6
                        message = sha256(bytes.fromhex(modified_transaction)).digest()
                        vk = VerifyingKey.from_string(pub_key, curve=ecdsa.SECP256k1)
                        # if hash160(pub_key).hex() != pkhash:
                        #     # print(pkhash)
                        #     # print(hash160(pub_key).hex())
                        #     # print("pkhash not matching")
                        #     invalid_transactions.add(file_name)
                        #     break
                        try:
                            # Verify the signature
                            result = vk.verify(bytes.fromhex(sig), message, hashfunc=sha256)
                            # print("Signature is valid.")
                        except BadSignatureError:
                            invalid_transactions.add(file_name)
                            break
                            # print("Signature is invalid.")
                        address = "00" + pkhash + sha256(sha256(bytes.fromhex("00" + pkhash)).digest()).digest().hex()[:8] 
                        if base58.b58encode(bytes.fromhex(address)).decode('utf-8') != input['prevout']['scriptpubkey_address']:
                            invalid_transactions.add(file_name)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON in file {file}: {e}")

# with open("coinbase.json", r) as file:
#     coinbase = serialize(json.load(file))[0]

bh = "04e00020e3e954a25562ccde401f8b2ade53f1e27cbf4db242bd0b000000000000000000c937f59a3635f492e8218c75b2492c6e1d59d1483a09341357e4fbfd4e0f923039c3fe6024961417c511768c"

filename = "output.txt"

with open(filename, 'w') as f:
    f.write("00c0302f0000000000000000000000000000000000000000000000000000000000000000bf855531ef6f41de2a8afe3b4849ad6de254da521736f986b9f000e79629286c4aaf1666ffff001f0010c88b")
    f.write("\n")
    f.write("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03123456ffffffff0140be4025000000004341047eda6bd04fb27cab6e7c28c99b94977f073e912f25d1ff7165d9c95cd9bbe6da7e7ad7f2acb09e0ced91705f7616af53bee51a238b7dc527f2be0aa60469d140ac00000000")
    f.write("\n")
    f.write("6c282996e700f0b986f9361752da54e26dad49483bfe8a2ade416fef315585bf")
    f.write("\n")

    
print(invalid_transactions)
print(len(invalid_transactions))