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
import os, time
import json
from hashlib import sha256
from serialisations import serialize, hash160, decode_sig, tx_weight
from verifications import verify_p2pkh, verify_p2wpkh, verify_p2wsh, verify_p2sh
import requests, itertools

def merkle_root(txids):
    if len(txids) == 0:
        return ""
    if len(txids) == 1:
        return bytes.fromhex(txids[0])[::-1].hex()
        return txids[0]
        # return bytes.fromhex(txids[0])[::-1].hex()
    # txids = [bytes.fromhex(txid)[::-1].hex() for txid in txids]
    while True:
        new_txids = []
        if len(txids) == 1:
            break
        if len(txids) % 2 == 1:
            txids.append(txids[-1])
        for i in range(0, len(txids), 2):
            new_txids.append(sha256(sha256(bytes.fromhex(txids[i]+txids[i+1])).digest()).digest().hex())
        txids = new_txids
    return bytes.fromhex(txids[0])[::-1].hex()
    # return txids[0]

def construct_block_header(txids):
    target = "0000ffff00000000000000000000000000000000000000000000000000000000"
    merkle = bytes.fromhex(merkle_root(txids))[::-1].hex()
    unix_time = bytes.fromhex(hex(int(time.time()))[2:])[::-1].hex()
    target_bits = bytes.fromhex("1f00ffff")[::-1].hex()
    header_pre_nonce = "00c0302f" + "0"*64 + merkle + unix_time + target_bits
    hex_chars = '0123456789ABCDEF'
    nonces = itertools.product(hex_chars, repeat=8)
    # print(header_pre_nonce)
    for nonce in nonces:
        nonce = ''.join(nonce)  
        block_header = header_pre_nonce + nonce
        if sha256(sha256(bytes.fromhex(block_header)).digest()).digest()[::-1] < bytes.fromhex(target):
            break
    # print(sha256(sha256(bytes.fromhex(block_header)).digest()).digest().hex())
    return block_header

def get_current_block_height():
    url = 'https://blockchain.info/latestblock'
    response = requests.get(url)
    if response.status_code == 200:
        block_data = response.json()
        return block_data.get('height')
    else:
        print('Failed to fetch block height:', response.status_code)
        return None

files = os.listdir('mempool') 
invalid_transactions = set([])
valid_transactions = set([])
transactions = set([])
ds_inputs = set([]) # set to check double spending of inputs
p2pkh_tx = {}
for i in range(len(files)): 
    file_name = files[i]
    with open('mempool/' + file_name, 'r') as file:
        try:
            data = json.load(file)
            # transactions.add(file_name)
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
            # if not wit:
            #     for j in range(len(data['vin'])):
            #         if data['vin'][j]['prevout']['scriptpubkey_type'] == "p2pkh":       
            #             is_valid = verify_p2pkh(data, j)                 
            #             if not is_valid:
            #                 invalid_transactions.add(file_name)
            #                 break
            # for j in range(len(data['vin'])):
            #     if data['vin'][j]['prevout']['scriptpubkey_type'] == "v0_p2wpkh":       
            #         transactions.add(file_name)
            #         is_valid = verify_p2wpkh(data, j)                 
            #         if not is_valid:
            #             invalid_transactions.add(file_name)
                        # break
            # for j in range(len(data['vin'])):
            #     if data['vin'][j]['prevout']['scriptpubkey_type'] == "v0_p2wsh":       
            #         transactions.add(file_name)
            #         is_valid = verify_p2wsh(data, j)                 
            #         if not is_valid:
            #             invalid_transactions.add(file_name)
            #             break

        except json.JSONDecodeError as e:
            print(f"Error decoding JSON in file {file}: {e}")

# for i in range(len(files)): 
#     file_name = files[i]
#     with open('mempool/' + file_name, 'r') as file:
#         try:
#             data = json.load(file)

#             # for j in range(len(data['vin'])):
#             #     if data['vin'][j]['prevout']['scriptpubkey_type'] == "v0_p2wpkh":       
#             #         transactions.add(file_name)
#             #         is_valid = verify_p2wpkh(data, j)                 
#             #         if not is_valid:
#             #             invalid_transactions.add(file_name)
#             #             break
                    
#             for j in range(len(data['vin'])):
#                 if data['vin'][j]['prevout']['scriptpubkey_type'] == "v0_p2wsh":       
#                     is_valid = verify_p2wsh(data, j)                 
#                     if not is_valid:
#                         invalid_transactions.add(file_name)
#                         break

#             # for j in range(len(data['vin'])):
#             #     if data['vin'][j]['prevout']['scriptpubkey_type'] == "p2sh":       
#             #         transactions.add(file_name)
#             #         is_valid = verify_p2sh(data, j)                 
#             #         if not is_valid:
#             #             invalid_transactions.add(file_name)
#             #             break

#         except json.JSONDecodeError as e:
#             print(f"Error decoding JSON in file {file}: {e}")

for i in range(len(files)): 
    file_name = files[i]
    with open('mempool/' + file_name, 'r') as file:
        try:
            data = json.load(file)
            for j in range(len(data['vin'])-1):
                if data['vin'][j]['prevout']['scriptpubkey_type'] != data['vin'][j+1]['prevout']['scriptpubkey_type']:
                    invalid_transactions.add(file_name)
                    break
            for j in range(len(data['vin'])):
                if data['vin'][j]['prevout']['scriptpubkey_type'] == "p2sh":       
                    transactions.add(file_name)
                    is_valid = verify_p2sh(data, j)                 
                    if not is_valid:
                        invalid_transactions.add(file_name)
                        break
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON in file {file}: {e}")

# with open("coinbase.json", r) as file:
#     coinbase = serialize(json.load(file))[0]

# bh = "04e00020e3e954a25562ccde401f8b2ade53f1e27cbf4db242bd0b000000000000000000c937f59a3635f492e8218c75b2492c6e1d59d1483a09341357e4fbfd4e0f923039c3fe6024961417c511768c"

filename = "output.txt"

# for element in transactions:
    # print(element)
# print(valid_transactions)

valid_transactions_new = set([])

# try:
#     with open(filename, 'r') as file:
#         # Read each line and append to the elements list
#         for line in file:
#             valid_transactions_new.add(line.strip())  # Remove whitespace characters like '\n'
# except FileNotFoundError:
#     print(f"Error: File '{filename}' not found.")

for tx in transactions:
    if tx not in invalid_transactions:
        valid_transactions.add(tx)

with open("filename.txt", 'w') as f:
    for tx in sorted(valid_transactions):
        f.write(tx)
        f.write("\n")

try:
    with open("filename.txt", 'r') as file:
        # Read each line and append to the elements list
        for line in file:
            valid_transactions_new.add(str(line.strip()))  # Remove whitespace characters like '\n'
except FileNotFoundError:
    print(f"Error: File txs.txt not found.")

# print(valid_transactions_new)

# print(len(invalid_transactions))
print(len(valid_transactions_new))
# print(len(transactions))

fees = 0
transaction_fees = {}
wtxids = []
wtxid_dict = {}
block_weight = 320 # size of block header at start
initial_block_weight = 320
# for i in range(len(valid_transactions)):
wtxids.append("0000000000000000000000000000000000000000000000000000000000000000")
for file_name in valid_transactions_new:
    # file_name = valid_transactions[i]
    with open('mempool/' + file_name, 'r') as file:
        try:
            block_weight += int(tx_weight(data))
            if block_weight > 3900000:
                break
            data = json.load(file)
            txid = sha256(sha256(bytes.fromhex(serialize(data)[1])).digest()).digest().hex()
            # print(block_weight)
            wtxid = sha256(sha256(bytes.fromhex(serialize(data)[0])).digest()).digest().hex()
            wtxid_dict[txid] = wtxid
            # print(file_name)
            # print(wtxid)
            # wtxids.append(bytes.fromhex(wtxid)[::-1].hex())
            # print(wtxids)
            input_sum = 0
            output_sum = 0
            for input in data['vin']:
                input_sum += input['prevout']['value']
            for output in data['vout']:
                output_sum += output['value']
            transaction_fees[file_name] = input_sum - output_sum
            fees += (input_sum - output_sum)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON in file {file}: {e}")
# print(wtxid_dict)
# wtxids = wtxids[:-1]
print(block_weight)
# print(wtxids)

transaction_fees = dict(sorted(transaction_fees.items(), key=lambda item: item[1], reverse=True))
for file_name in transaction_fees:
    # file_name = valid_transactions[i]
    with open('mempool/' + file_name, 'r') as file:
        try:
            data = json.load(file)
            txid = sha256(sha256(bytes.fromhex(serialize(data)[1])).digest()).digest().hex()
            # print(txid)
            wtxids.append(bytes.fromhex(wtxid_dict[txid])[::-1].hex())
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON in file {file}: {e}")
# print(transaction_fees)
# print(transaction_fees)

block_arr = []

with open("coinbase.json", 'r') as file:
    try:
        coinbase_data = json.load(file)
        coinbase_data['vin'][0]['scriptsig'] = ""
        block_height = get_current_block_height()
        coinbase_data['vin'][0]['scriptsig'] = "03" + block_height.to_bytes(3, 'little').hex()
        coinbase_data['vin'][0]['scriptsig'] += "184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100" # dummy data
        coinbase_data['vout'][0]['value'] = 625000000 + fees
        wtxid_hash_reserve = bytes.fromhex(merkle_root([bytes.fromhex(tx)[::-1].hex() for tx in wtxids]))[::-1].hex() + coinbase_data['vin'][0]['witness'][0]
        print(wtxid_hash_reserve)
        coinbase_data['vout'][1]['scriptpubkey'] = "6a24aa21a9ed" + sha256(sha256(bytes.fromhex(wtxid_hash_reserve)).digest()).digest().hex()
        block_weight += tx_weight(coinbase_data)
        print(coinbase_data)
        print(serialize(coinbase_data))
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in file {file}: {e}")

block_arr.append(serialize(coinbase_data)[0])
block_arr.append(sha256(sha256(bytes.fromhex(serialize(coinbase_data)[1])).digest()).digest().hex())

for txname in transaction_fees:
    # if block_weight > 2000: 
        # break
    with open('mempool/' + txname, 'r') as file:
        try:
            data = json.load(file)
            txid = sha256(sha256(bytes.fromhex(serialize(data)[1])).digest()).digest().hex()
            block_arr.append(txid)
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON in file {file}: {e}")

block_header = construct_block_header(block_arr[1:])
block_arr = [block_header] + block_arr
    
try:
    # Open the file in write mode
    with open("output.txt", 'w') as file:
        # Write each element of the list to the file
        for element in block_arr[:2]:
            file.write(element + '\n')
        for element in block_arr[2:]:
            file.write(bytes.fromhex(element)[::-1].hex() + '\n') 

except Exception as e:
    print(f"Error writing to file: {e}")