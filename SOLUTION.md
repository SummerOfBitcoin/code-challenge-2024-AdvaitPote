# Summer of Bitcoin 2024 challenge: Solution Overview

## Design Approach
The block in this assignment comprises of three parts: the Block Header, the serialized coinbase transaction, and the list of all transactions. To construct the Block Header, we need all the transactions to be added to the block. Hence, the first part of the assignment is validating all transactions and eliminating invalid transactions. Then, the valid transactions are sorted in decreasing order by fees. 

The objective of a miner is to maximise his/her fees while keeping the block weight below `4000000`. Hence, the reverse-sorted valid transactions list is parsed from the beginning and added to a final transactions list of TXIDs till the total weight of the block reaches the block weight limit. 

Using this final transactions list, the coinbase transaction is constructed. This includes calculating the cumulative fees, adding the current block height, and the Witness commitment. This coinbase transaction is then prepended to the block. After that, it is followed by the coinbase TXID and then the rest of the transactions in order by the final transactions list. (the `coinbase.json` file is just a dummy coinbase transaction file which is then modified by the function. All existing fields in `coinbase.json` are either dummy values to be replaced or other fields not necessary to the functioning of the block).

Finally, the block header is constructed. The merkle root of all TXIDs is calculated and the previous block hash and version are set to arbitrary values. The UNIX time is imported and the target is converted to target bits of 4 bytes. The Block header is assembled and appended by 4 bytes for the nonce. The process then iterates through all possible nonce values and checks if the `hash256` of the block header is less than the target

## Implementation Details
The mining starts with iterating through all json files in the mempool. The transaction is then serialized using the `serialize` method in `serialisations.py` which returns the segwit-serialization and the legacy-serialization in order. Some minor validity checks are done first namely, transaction sizes, empty input/output lists, input/output amount to be below 21M BTC, locktime, and double spending. After that, all transactions are verified by the four main verifying functions `verify_p2pkh`, `verify_p2wpkh`, `verify_p2sh`, and `verify_p2wsh` depending on the transaction input types. 

Each of these validating functions are present in `verifications.py` (For transaction types P2SH and P2WSH, transactions with different input types are disqualified due to them not being compatible with and mismatching in witness commitment calculations).

```
def verify_tx_type:
    check `pkhash` matching
    draft message/transaction preimage and check if the signature is matching
    verify address with base58/bech32 encoding of pkhash
```

The TXID is basically the reverse byte form of `hash256` of the legacy serialization. Similarly, the WTXID is the same but for segwit serialization. `transaction_fees` is a dictionary made after all valid transactions are obtained mapping a transaction to its fees which is reverse-sorted. We then get our final transactions list after parsing through `transaction_fees` till the weight of all transactions exceeds the limit (block weight limit is slightly reduced to handle some mismatching calculations of block weights and hence as a safe cushion). A separate `wtxid_dict` maps Transactions to WTXIDs and also corrected as per the order of `transaction_fees`.

After this, the coinbase transaction is constructed. The current block height is added to the `scriptsig` of the input. The total fees is calculated and added to the first transaction output. Thw witness commitment is calculated as the merkle root of all WTXIDs in `wtxid_dict` and added to the second transaction output. 

Finally, the Block Header is constructed using `construct_block_header` from the serialized coinbase transaction and our list of transactions. The header pre nonce is appended with all possible nonces and hashed to check which one (reversed) comes out to be less than the target.

## Results and Performance

```
Score: 90
Fee: 17114981
Weight: 3888855
Max Fee: 20616923
```

In comparison to Max Fee, we get a fee attaining efficiency of `80%` to `85%`. A reason for the inefficiencies can be that we have to keep the block weight limit lower than usual for reasons mentioned above. Moreover, the code currently does not include the P2TR transactions. Due to some complications in processing P2TR transactions or some intricacies somewhere else, including P2TR transactions tends to reduce fees and the overall score which can be corrected.

## Conclusion
This assignment helps us outline the rough workflow of a miner. From verifying transactions to drafting functions for the constructuction of merkle roots, block headers, etc, working in this domain has helped us translate what we learnt in the recent weeks to a practical project. The working of a component has to be studied down to the most intricate detail when implementing it in real life which makes concepts stronger.

## References
- [Learn me a Bitcoin](https://learnmeabitcoin.com/)
- [Grokking Bitcoin by Kalle Rosenbaum](https://rosenbaum.se/book/)
