import os
import json
from ecdsa import VerifyingKey, SECP256k1
import hashlib
import binascii
import time
import sys

MAX_BLOCK_SIZE_BYTES = 1000000
# Path to mempool folder containing transaction files
MEMPOOL_FOLDER = "./mempool"

PUBLIC_KEYS_DIR = "./public_keys"


def calculate_base_size(transaction):
    base_size = 8  # version (4 bytes) + locktime (4 bytes)

    # Calculate size for each input
    for vin in transaction['vin']:
        base_size += 32  # txid (32 bytes)
        base_size += 4   # vout (4 bytes)

        # Calculate ScriptSig length
        script_sig_length = len(vin.get('scriptsig', '')) // 2  # Convert hex string length to bytes
        base_size += script_sig_length + 1  # scriptsig length (1 byte) + scriptSig length

        base_size += 4   # sequence (4 bytes)

    # Calculate size for each output
    for vout in transaction['vout']:
        base_size += 8   # value (8 bytes)
        base_size += 1   # scriptpubkey length (1 byte)
        base_size += len(vout['scriptpubkey']) // 2  # scriptpubkey length (variable)

    return base_size

def calculate_total_size(transaction):
    total_size = 0

    # Add witness data size for SegWit transactions
    for vin in transaction['vin']:
        if 'witness' in vin and vin['witness']:
            # Include witness marker (1 byte) and flag (1 byte)
            total_size += 2
            # Add witness stack size
            total_size += len(vin['witness']) * 64  # Assuming witness stack items are 64 bytes each

    return total_size

def calculate_transaction_weight(transaction):
    base_size = calculate_base_size(transaction)
    total_size = calculate_total_size(transaction)

    weight = 4 * base_size + total_size
    return weight



def calculate_transaction_weights(transactions):
    # Calculate weights for each transaction
    transaction_weights = []
    for transaction in transactions:
        weight = calculate_transaction_weight(transaction)
        transaction_weights.append((transaction, weight))

    # Sort transactions by weight (ascending order)
    transaction_weights.sort(key=lambda x: x[1])

    return transaction_weights


def trim_transactions(transactions, max_weight):
    sorted_transaction_weights = calculate_transaction_weights(transactions)
    selected_transactions = []
    current_weight = 0

    for transaction, weight in sorted_transaction_weights:
        if current_weight + weight <= max_weight:
            selected_transactions.append((transaction, weight))
            current_weight += weight
        else:
            break

    return selected_transactions, current_weight


def load_public_key(address):
    """ Load public key from file based on address """
    filename = os.path.join(PUBLIC_KEYS_DIR, f"{address}.pub")
    if not os.path.exists(filename):
        return None
    with open(filename, 'r') as file:
        public_key_hex = file.read().strip()
        return VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)


def convert_timestamp_to_hex(timestamp):
    # Convert the timestamp integer to a little-endian hexadecimal format (4 bytes)
    timestamp_hex = timestamp.to_bytes(4, byteorder='little', signed=False).hex()
    return timestamp_hex

def convert_version_to_hex(version):
    # Convert version string to an integer
    version_int = int(version)

    # Convert integer to little-endian byte representation (4 bytes)
    version_bytes = version_int.to_bytes(4, byteorder='little', signed=False)

    # Convert byte sequence to hexadecimal string (little-endian format)
    version_hex = version_bytes.hex()

    return version_hex

def convert_bits_to_hex(bits):
    # Convert bits field to hexadecimal format (reverse byte order)
    # Extract precision and shift information
    precision = int(bits[-6:], 16)
    shift = int(bits[:2], 16)

    # Construct the new bits value in desired format
    new_bits = f"{precision:06x}{shift:02x}"

    return new_bits

def calculate_block_header(version, prev_block_hash, merkle_root, timestamp, bits, nonce):
    block_header = f"{version}{prev_block_hash}{merkle_root}{timestamp}{bits}{nonce}"
    return block_header


def little_endian_bytes(value, length):
    return value.to_bytes(length, byteorder='little')

def varint_encode(value):
    if value < 0xfd:
        return value.to_bytes(1, 'little')
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')



def little_endian_bytes(value, length):
    return value.to_bytes(length, byteorder='little')

def varint_encode(value):
    if value < 0xfd:
        return value.to_bytes(1, 'little')
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')


def serialize_transaction(transactions):
  txid_array = []
  rev_txid_array = []
  for transaction in transactions:
    version = transaction['version']
    locktime = transaction['locktime']
    inputs = transaction['vin']
    outputs = transaction['vout']

    # Start building the transaction byte array
    tx_data = (
        little_endian_bytes(version, 4) +
        varint_encode(len(inputs))
    )

    # Process each input
    for input in inputs:
        txid = bytes.fromhex(input['txid'])[::-1]  # Reverse txid for little-endian
        prev_tx_out_index = input['vout']
        scriptsig = bytes.fromhex(input['scriptsig'])
        sequence = input['sequence']

        # Append txid, prev_tx_out_index, scriptsig
        tx_data += (
            txid +
            little_endian_bytes(prev_tx_out_index, 4) +
            varint_encode(len(scriptsig)) +
            scriptsig +
            little_endian_bytes(sequence, 4)
        )

    # Output count
    tx_data += varint_encode(len(outputs))

    # Process each output
    for output in outputs:
        value = output['value']
        script_pubkey = bytes.fromhex(output['scriptpubkey'])

        # Append output value, script_pubkey
        tx_data += (
            little_endian_bytes(value, 8) +
            varint_encode(len(script_pubkey)) +
            script_pubkey
        )

    # Calculate wtxid (hash of tx_data with marker and flag)
    tx_data += little_endian_bytes(locktime, 4)
    ser_tx_hash = hashlib.sha256(hashlib.sha256(tx_data).digest()).digest()
    txid_array.append(ser_tx_hash.hex())
    rev_txid_array.append(ser_tx_hash[::-1].hex())

  return txid_array, rev_txid_array, tx_data.hex(), ser_tx_hash[::-1].hex()


def wit_serialize_transaction(transactions):
  wtxid_array = ['0000000000000000000000000000000000000000000000000000000000000000']
  for transaction in transactions:
    version = transaction['version']
    locktime = transaction['locktime']
    inputs = transaction['vin']
    outputs = transaction['vout']

    # Start building the transaction byte array
    tx_data = (
        varint_encode(len(inputs))
    )

    # Process each input
    for input in inputs:
        txid = bytes.fromhex(input['txid'][::-1])  # Reverse txid for little-endian
        prev_tx_out_index = input['vout']
        scriptsig = bytes.fromhex(input['scriptsig'])
        sequence = input['sequence']

        # Append txid, prev_tx_out_index, scriptsig
        tx_data += (
            txid +
            little_endian_bytes(prev_tx_out_index, 4) +
            varint_encode(len(scriptsig)) +
            scriptsig +
            little_endian_bytes(sequence, 4)
        )

    # Output count
    tx_data += varint_encode(len(outputs))

    # Process each output
    for output in outputs:
        value = output['value']
        script_pubkey = bytes.fromhex(output['scriptpubkey'])

        # Append output value, script_pubkey
        tx_data += (
            little_endian_bytes(value, 8) +
            varint_encode(len(script_pubkey)) +
            script_pubkey
        )
  # Append locktime

    # If transaction has witness data, append it before hashing
    if any('witness' in vin for vin in inputs):
        for input in inputs:
            if 'witness' in input:
                for witness_item in input['witness']:
                    tx_data += varint_encode(len(witness_item) // 2)  # Length of witness item in bytes
                    tx_data += bytes.fromhex(witness_item)
                    marker = bytes.fromhex('00')
                    flag = bytes.fromhex('01')
                    tx_data = marker + flag + tx_data  # Add segwit marker and flag
    # Calculate wtxid (hash of tx_data with marker and flag)
    tx_data += little_endian_bytes(locktime, 4)
    wtxid_data = little_endian_bytes(version, 4) + tx_data
    wtxid_hash = hashlib.sha256(hashlib.sha256(wtxid_data).digest()).digest()
    if 'witness' in input:
     wtxid_array.append(wtxid_hash[::-1].hex())

  return wtxid_array, wtxid_data.hex(), wtxid_hash.hex(), wtxid_hash[::-1].hex()



def serialize_coinbase(transactions):
 for transaction in transactions:
    version = transaction['version']
    locktime = transaction['locktime']
    inputs = transaction['vin']
    outputs = transaction['vout']

    # Start building the transaction byte array
    tx_data = (
        varint_encode(len(inputs))
    )

    # Process each input
    for input in inputs:
        txid = bytes.fromhex(input['txid'][::-1])  # Reverse txid for little-endian
        prev_tx_out_index = input['vout']
        scriptsig = bytes.fromhex(input['scriptsig'])
        sequence = input['sequence']

        # Append txid, prev_tx_out_index, scriptsig
        tx_data += (
            txid +
            little_endian_bytes(prev_tx_out_index, 4) +
            varint_encode(len(scriptsig)) +
            scriptsig +
            little_endian_bytes(sequence, 4)
        )

    # Output count
    tx_data += varint_encode(len(outputs))

    # Process each output
    for output in outputs:
        value = output['value']
        script_pubkey = bytes.fromhex(output['scriptpubkey'])

        # Append output value, script_pubkey
        tx_data += (
            little_endian_bytes(value, 8) +
            varint_encode(len(script_pubkey)) +
            script_pubkey
        )
  # Append locktime

    # If transaction has witness data, append it before hashing
    if any('witness' in vin for vin in inputs):
        for input in inputs:
            if 'witness' in input:
                for witness_item in input['witness']:
                    tx_data += bytes.fromhex('01')
                    tx_data += varint_encode(len(witness_item) // 2)  # Length of witness item in bytes
                    tx_data += bytes.fromhex(witness_item)
                    marker = bytes.fromhex('00')
                    flag = bytes.fromhex('01')
                    tx_data = marker + flag + tx_data  # Add segwit marker and flag
    # Calculate wtxid (hash of tx_data with marker and flag)
    tx_data += little_endian_bytes(locktime, 4)
    wtxid_data = little_endian_bytes(version, 4) + tx_data
    wtxid_hash = hashlib.sha256(hashlib.sha256(wtxid_data).digest()).digest()

 return wtxid_data.hex(), wtxid_hash[::-1].hex()

def compute_witness_commitment(witness_root_hash):

    reserved_value = "0000000000000000000000000000000000000000000000000000000000000000"
    # Convert witness root hash and reserved value to bytes
    witness_root_hash_bytes = bytes.fromhex(witness_root_hash)
    reserved_value_bytes = bytes.fromhex(reserved_value)

    # Concatenate witness root hash and reserved value
    concatenated_data = witness_root_hash_bytes + reserved_value_bytes

    # Perform SHA-256 hashing twice (SHA-256d)
    sha256_hash = hashlib.sha256(concatenated_data).digest()
    sha256d_hash = hashlib.sha256(sha256_hash).digest()

    # Derive the wTXID commitment (hexadecimal representation)
    wtxid_commitment = sha256d_hash.hex()  # Reverse bytes for little-endian

    return wtxid_commitment

def create_coinbase(wTXID_commit, block_Height):
     coinbase_struct = [{
        "version": 2,
        "locktime": 0,
        "vin": [
         {
          "txid": "0000000000000000000000000000000000000000000000000000000000000000",
          "vout": 1,
          "prevout": {
            "scriptpubkey": "001481897cd2113b1b0bf0e718cc791d9bd2d246c555",
            "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 81897cd2113b1b0bf0e718cc791d9bd2d246c555",
            "scriptpubkey_type": "v0_p2wpkh",
            "scriptpubkey_address": "bc1qsxyhe5s38vdshu88rrx8j8vm6tfyd324l640wa",
            "value": 0
          },
        "scriptsig": "03" + block_Height + "10076c0000946e0100",
        "witness": [
            "0000000000000000000000000000000000000000000000000000000000000000"
        ]
        ,
        "is_coinbase": True,
        "sequence": 0
        }
        ],
        "vout": [
        {
         "scriptpubkey": "76a914acd783f632ad040fc72d9a06ec17ffb2d8a97a5d88ac",
         "scriptpubkey_asm": "OP_DUP OP_HASH160 OP_PUSHBYTES_20 acd783f632ad040fc72d9a06ec17ffb2d8a97a5d OP_EQUALVERIFY OP_CHECKSIG",
         "scriptpubkey_type": "p2pkh",
         "scriptpubkey_address": "1GkuQGoy1erCJfQKY9AGC75rttCBQRtGer",
         "value": 0
        },
        {
        "scriptpubkey": "6a24aa21a9ed"+ wTXID_commit,
        "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 56789b58e00f0a9e866e2a4ea0b0d97e839c4b0d",
        "scriptpubkey_type": "v0_p2wpkh",
        "scriptpubkey_address": "bc1q2eufkk8qpu9fapnw9f82pvxe06pecjcd7ea2x0",
        "value": 0
       }
    ],
    "witness": [{
            "0": {
                "size": "01",
                "item": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        }
        ]
    }]
     return coinbase_struct


def validate_transaction(transaction):
    try:
        # Check transaction structure
        if not transaction.get('vin') or not transaction.get('vout'):
            return False
        
        vin = transaction.get('vin', [])
        vout = transaction.get('vout', [])
        total_input_value = 0
        total_output_value = 0
        spent_outputs = set()  # Set to track spent outputs
        
        transaction_size_bytes = sys.getsizeof(json.dumps(transaction))

        # Check transaction size against MAX_BLOCK_SIZE_BYTES
        if transaction_size_bytes > MAX_BLOCK_SIZE_BYTES or transaction_size_bytes < 100:
            return False
        
        # Validate each input (vin)
        for input in vin:
            if input.get('hash') == '0' and input.get('N') == -1:
                return False  # Reject coinbase transactions
            
            txid = input['txid']
            vout_index = input['vout']
            prevout = input.get('prevout', {})
            scriptpubkey_type = prevout.get('scriptpubkey_type', '')
            scriptpubkey_address = prevout.get('scriptpubkey_address', '')
            input_value = prevout.get('value', 0)
            
            # Ensure 'txid' is present in the input
            if 'txid' not in input:
                return False
            # Check for double spend (already spent outputs)
            if (txid, vout_index) in spent_outputs:
                return False
            
            # Validate input based on scriptpubkey type
            if scriptpubkey_type not in ['v1_p2tr', 'v0_p2wpkh', 'p2sh', 'p2pkh', 'p2wsh']:
                return False
            
            # Calculate total input value
            total_input_value += input_value
            
            # Mark the input's previous output as spent
            spent_outputs.add((txid, vout_index))
            # Additional validation rules based on scriptpubkey type can be added here
            
            # Verify signature (if applicable)
            if scriptpubkey_type == 'p2pkh' or scriptpubkey_type == 'p2wpkh':
                signature = input.get('signature', '')
                public_key = load_public_key(scriptpubkey_address)
                if not public_key:
                    return False
                if not public_key.verify(signature, bytes.fromhex(input['txid'])):
                    return False
            
            # Validate output based on scriptpubkey type
            if scriptpubkey_type == 'v1_p2tr':
                # Validation logic for v1_p2tr (Taproot) outputs
                # Specific validation rules for Taproot outputs (v1_p2tr) can be added here
                pass
            
            elif scriptpubkey_type == 'v0_p2wpkh':
                # Validation logic for v0_p2wpkh (SegWit) outputs
                if not scriptpubkey_address.startswith('bc1'):
                    return False
                if input_value <= 0:
                    return False
            
            elif scriptpubkey_type == 'p2sh':
                # Validation logic for p2sh (Pay to Script Hash) outputs
                # Specific validation rules for P2SH outputs can be added here
                pass
            
            
            elif scriptpubkey_type == 'p2pkh':
                # Validation logic for p2pkh (Pay to Public Key Hash) outputs
                if not scriptpubkey_address.startswith('1'):
                    return False
                if input_value <= 0:
                    return False
            
            elif scriptpubkey_type == 'p2wsh':
                # Validation logic for p2wsh (SegWit) outputs
                if not scriptpubkey_address.startswith('bc1'):
                    return False
                if input_value <= 0:
                    return False
                
        # Validate each output (vout)
        for output in vout:
            scriptpubkey_type = output.get('scriptpubkey_type', '')
            scriptpubkey_address = output.get('scriptpubkey_address', '')
            output_value = output.get('value', 0)
            
            # Validate output based on scriptpubkey type
            if scriptpubkey_type not in ['v1_p2tr', 'v0_p2wpkh', 'p2sh', 'p2pkh', 'p2wsh']:
                return False
            
            # Calculate total output value
            total_output_value += output_value

            # Check input-output balance condition
            if total_input_value < total_output_value:
             return False
            
            # Validate output based on scriptpubkey type
            if scriptpubkey_type == 'v1_p2tr':
                # Validation logic for v1_p2tr (Taproot) outputs
                # Specific validation rules for Taproot outputs (v1_p2tr) can be added here
                pass
            
            elif scriptpubkey_type == 'v0_p2wpkh':
                # Validation logic for v0_p2wpkh (SegWit) outputs
                if not scriptpubkey_address.startswith('bc1'):
                    return False
                if output_value <= 0:
                    return False
            
            elif scriptpubkey_type == 'p2sh':
                # Validation logic for p2sh (Pay to Script Hash) outputs
                # Specific validation rules for P2SH outputs can be added here
                pass
            
            
            elif scriptpubkey_type == 'p2pkh':
                # Validation logic for p2pkh (Pay to Public Key Hash) outputs
                if not scriptpubkey_address.startswith('1'):
                    return False
                if output_value <= 0:
                    return False
            
            elif scriptpubkey_type == 'p2wsh':
                # Validation logic for p2wsh (SegWit) outputs
                if not scriptpubkey_address.startswith('bc1'):
                    return False
                if output_value <= 0:
                    return False
            # Additional validation rules based on scriptpubkey type can be added here
        
        return True  # Transaction is valid if all checks pass
    
    except Exception as e:
        print(f"Error validating transaction: {str(e)}")
        return False

def write_transaction_ids(output_file, trxn_ids):
    for trxn_id in trxn_ids:
            output_file.write(f"{trxn_id}\n")


def merkle_root(ser_txids):
    # Compute Merkle root hash using the extracted txids
    if len(ser_txids) == 0:
        return None

    while len(ser_txids) > 1:
        next_level = []
        # Pair and hash the txids
        for i in range(0, len(ser_txids), 2):
            if i + 1 < len(ser_txids):  # Ensure we have pairs
                hash_pair = hash2(ser_txids[i], ser_txids[i+1])
            else:  # If odd number of txids, hash with itself
                hash_pair = hash2(ser_txids[i], ser_txids[i])
            next_level.append(hash_pair)
        ser_txids = next_level  # Update txids to next level
    
    return ser_txids[0] if ser_txids else None

def hash2(a, b):
    # Reverse inputs before and after hashing due to endian issues
    a1 = bytes.fromhex(a)[::-1]
    b1 = bytes.fromhex(b)[::-1]
    concat_bytes = a1 + b1
    first_hash = hashlib.sha256(concat_bytes).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    final_hash_hex = second_hash[::-1].hex()
    
    return final_hash_hex


def reverse_byte_order(hex_string):
    # Convert the hexadecimal string to bytes
    byte_sequence = bytes.fromhex(hex_string)

    # Reverse the byte order
    reversed_byte_sequence = byte_sequence[::-1]

    # Convert the reversed byte sequence back to hexadecimal
    reversed_hex_string = reversed_byte_sequence.hex()

    return reversed_hex_string


def calculate_block_hash(block_header):
    try:
        # Encode the block header string as bytes using UTF-8 encoding
        block_header_bytes = bytes.fromhex(block_header)
        # Calculate double SHA-256 hash
        hash_1 = hashlib.sha256(block_header_bytes).digest()
        hash_2 = hashlib.sha256(hash_1).digest()
        # Return the hash as a hexadecimal string
        return hash_2
    except Exception as e:
        print(f"Error calculating block hash: {str(e)}")
        return None
    


    
def mine_block(txids, prev_block_hash, difficulty_target, merkle_root, ser_coinbase_trxn):
   # Convert version and bits to hexadecimal format
    version_hex = "00000004"
    bits = "ffff001f"
    timestamp = int(time.time())  # Current Unix timestamp
    timestamp_hex = timestamp.to_bytes(4, byteorder='little').hex()
    nonce = 0

    while True:
        nonce_hex = nonce.to_bytes(4, byteorder='little', signed=False).hex()

        # Construct the block header
        block_header = version_hex + prev_block_hash + merkle_root + timestamp_hex + bits + nonce_hex
        
        # Calculate the block hash
        block_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(block_header)).digest()).digest()
        # Check if the block hash meets the difficulty target
        if int.from_bytes(block_hash[::-1], byteorder='big') < int(difficulty_target, 16):
            print(f"Block mined! Nonce: {nonce}")

            # Write block header, serialized coinbase transaction, and txids to output file
            with open('output.txt', 'w') as output_file:
                output_file.write(block_header + '\n')
                output_file.write(ser_coinbase_trxn + '\n')
                write_transaction_ids(output_file, txids)  # Write transaction IDs to output file
            return block_header, block_hash[::-1].hex()

        # Increment the nonce and try again
        nonce += 1
def main():
    transactions = []

    try:
        # Read all transaction files from mempool folder
        for filename in os.listdir(MEMPOOL_FOLDER):
            with open(os.path.join(MEMPOOL_FOLDER, filename), 'r') as file:
                transaction_data = json.load(file)
                transactions.append(transaction_data)
        
        print(f"Number of transactions read from mempool: {len(transactions)}")


        # Filter transactions to include only those with valid 'vin' and 'txid'
        valid_transactions = [tx for tx in transactions if validate_transaction(tx)]
        print(f"Number of valid transactions read from mempool: {len(valid_transactions)}")
        
        max_total_weight = 3000000  # Maximum cumulative weight allowed (4 million weight units)

        # Trim transactions to meet the weight constraint
        selected_transactions, total_weight = trim_transactions(valid_transactions, max_total_weight)
        print(f"Total Cumulative Weight: {total_weight}")
        block_trxns = []
        for transaction, weight in selected_transactions:
          block_trxns.append(transaction)

        
        print(f"Number of valid transactions in block: {len(block_trxns)}")

        txids, rev_trxn_ids, ser_trxn, ser_tx_id = serialize_transaction(block_trxns)
        wtxids, ser_wit_trxn, wtxid, rev_wtxid = wit_serialize_transaction(block_trxns)

        wit_hash = merkle_root(wtxids)
        wit_commitment = compute_witness_commitment(wit_hash)
        print(f"{wit_commitment}")
        coinbase_trxn_struct = create_coinbase(wit_commitment, "951a06")

        ser_coinbase_trxn, rev_ser_coinbase_trxn_id = serialize_coinbase(coinbase_trxn_struct)
        print(f"ser_coinbase:{ser_coinbase_trxn}")
        print(f"rev_coinbase_id:{rev_ser_coinbase_trxn_id}")
        rev_trxn_ids.insert(0, rev_ser_coinbase_trxn_id)

        
        calc_merkle_root = merkle_root(rev_trxn_ids)
        print(f"mekle root:{calc_merkle_root}")
        nat_order_merkle_root = reverse_byte_order(calc_merkle_root)
        print(f"nat mekle root:{nat_order_merkle_root}")
        # Placeholder values for previous block hash and difficulty target
        prev_block_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        difficulty_target = "0000ffff00000000000000000000000000000000000000000000000000000000"
        
        # Mine the block using transactions from the mempool
        block_header, block_hash = mine_block(rev_trxn_ids, prev_block_hash, difficulty_target, nat_order_merkle_root, ser_coinbase_trxn)


        print(f"Block Header: {block_header}")
        print(f"Block Hash: {block_hash}")
        print(f"Coinbase Transaction: {coinbase_trxn_struct}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
