# Bitclamp: a cryptocurrency-based publication tool
# Copyright (C) 2016  Joe Testa <jtesta@positronsecurity.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms version 3 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# This program is called by bitcoind/dogecoind every time it finds a new block.
# It extracts data and re-assembles files found in the blockchain.

import atexit, binascii, fcntl, json, os, pickle, struct, sys
from Publication import *
from Utils import *
from PartialFile import *
from RPCClient import *

debug = False
fd = None
lock_fd = None

# Called when the program terminates.  It closes the log file handle and
# releases the output directory lock.
def exit_func():
    if fd is not None:
        fd.close()
    if lock_fd is not None:
        lock_fd.close()


# Writes a message to the log file.
def log(s):
    fd.write(s + "\n")
    fd.flush()


# Writes a message to the log file only if debugging is enabled.
def d(s):
    if debug:
        log(s)


# Decrypts a deadman switch file, given a key.  Stores the decrypted file
# in the output directory.  Returns True on success, or False if no matching
# deadman switch file was found (or an error occurred).
def decrypt_deadman_switch_file(partial_files, data):
    txid_hex = binascii.hexlify(data[0:32]).decode('ascii')
    key = data[32:64]
    iv = data[64:96]
    extra = data[96:128]

    # Loop through all partial files and look for one whose initial TXID
    # matches the deadman switch key data.  Then decrypt and properly store
    # the file.
    for partial_file in partial_files:
        if txid_hex == partial_file.initial_txid:
            partial_file.debug_func = d
            return partial_file.finalize(key)

    log('Failed to find a matching deadman switch file with TXID: %s' % txid_hex)
    return False


# Processes a block by inspecting its transactions and parsing any included
# data.
def handle_block(current_block_hash, current_block = None):

    # If the parsed block wasn't provided, parse it now.
    if current_block is None:
        current_block = rpc_client.getblock(current_block_hash)

    # Load all the partial files.
    partial_files = PartialFile.load_state_files(d, partial_dir)
    d("Loaded %d partial files" % len(partial_files))

    # Get all the interesting TXIDs so we know what to look for in this block.
    interesting_txids = {}
    for partial_file in partial_files:
        previous_txids = partial_file.get_previous_txids()
        for previous_txid in previous_txids:
            d("Interesting TXID: %s" % previous_txid)
            interesting_txids[previous_txid] = partial_file

    # Get the transactions in this block.  Loop through each one and parse it.
    txids = current_block['tx']
    for txid in txids:
        bytes_to_write = b''
        file_offset = -1
        partial_file = None

        raw_tx = rpc_client.getrawtransaction(txid, 1)
        vins = raw_tx['vin']
        for vin in vins:
            if 'txid' in vin:
                vin_txid = vin['txid']
                scriptSig_hex = vin['scriptSig']['hex']
                scriptSig_bin = binascii.unhexlify(scriptSig_hex)

                # Look for the header denoting the start of a new file.
                header_pos = scriptSig_bin.find(Publication.HEADER_BEGIN)
                if header_pos >= 2:
                    d("Found potential publication header in %s" % txid)

                    start_pos = header_pos - 2
                    data = b''
                    n = 0
                    while start_pos + 34 < len(scriptSig_bin):
                        if scriptSig_bin[start_pos:start_pos+2] != b'\x21\x02':
                            break

                        start_pos += 2
                        data_segment = scriptSig_bin[start_pos:start_pos + 32]
                        data += data_segment
                        start_pos += 32

                        # Only up to 14 keys/data segments may be present.
                        n += 1
                        if n == 14:
                            break

                    if len(data) < 92:
                        continue


                    header_bytes_len = len(Publication.HEADER_BEGIN)

                    ptr = header_bytes_len
                    nonce = data[ptr:ptr + Publication.NONCE_LEN]
                    ptr += Publication.NONCE_LEN
                    nonce_hash = data[ptr:ptr + 32]
                    ptr += 32

                    # Compute the hash on the nonce and salt and see if they
                    # match what is in the header.  This helps prevent false
                    # positives.
                    computed_nonce_hash = hashlib.sha256(Publication.NONCE_SALT + nonce).digest()
                    if nonce_hash != computed_nonce_hash:
                        log("Nonce hash does not match!")
                        d("Computed hash: %s; extracted: %s" % (binascii.hexlify(computed_nonce_hash), binascii.hexlify(nonce_hash)))
                        continue
                    else:
                        d("Nonce hashes match.")

                    # Skip over the two reserved bytes.
                    reserved = data[ptr:ptr + 2]
                    ptr += 2

                    # general flags, encryption, content, compression, file_size
                    geccfs = data[ptr:ptr + 8]
                    ptr += 8

                    general_flags, encryption_type, content_type, compression_type, file_size = struct.unpack('!BBBBI', geccfs)
                    file_hash = data[ptr:ptr + 32]
                    ptr += 32

                    # filename length, description length
                    fldl = data[ptr:ptr + 2]
                    ptr += 2
                    filename_len, description_len = struct.unpack('!BB', fldl)
                    filename_len = min(filename_len, 128)
                    description_len = min(description_len, 128)

                    filename = ''
                    description = ''
                    if (filename_len > 0) and ((ptr + filename_len) < len(data)):
                        filename = data[ptr:ptr + filename_len].decode('utf-8')
                        ptr += filename_len

                    if (description_len > 0) and ((ptr + description_len) < len(data)):
                        description = data[ptr:ptr + description_len].decode('utf-8')
                        ptr += description_len


                    data = data[ptr:]

                    # Strip out any relative paths embedded into the filename.
                    # The basename() call is enough, but we'll throw in some
                    # manual replacement just to be extra sure.
                    sanitized_filename = os.path.basename(filename).replace('\\', '').replace('/', '')

                    partial_file = PartialFile(d, txid, output_dir, partial_dir, sanitized_filename, description, file_size, general_flags, encryption_type, content_type, compression_type, file_hash)

                    # Is this a deadman switch key?  If so, ensure that the
                    # payload has at least 128 bytes (it should be exactly 128,
                    # but there may be padding at this point still).
                    if partial_file.is_deadman_switch_key() and (len(data) >= 128):
                        log('DISCOVERED DEADMAN SWITCH KEY!: ' + binascii.hexlify(data).decode('ascii'))
                        if decrypt_deadman_switch_file(partial_files, data):
                            log('Successfully decrypted deadman switch file!')
                        else:
                            log('Failed to decrypt deadman switch file.')
                    else:
                        log("Discovered publication: %s" % partial_file)

                        partial_file.write_data(data, 0)
                        partial_file.save_state()
                        partial_file = None

                # Header bytes not found.  Let's check this transaction
                # references any TXIDs that we've previously processed.  If 
                # present, this would mean they have continuation data we need
                # to extract.
                else:
                    if vin_txid in interesting_txids:
                        data = Utils.get_data_from_scriptsig(d, scriptSig_bin)
                        partial_file = interesting_txids[vin_txid]

                        termination_data = False
                        noop_data = False

                        # Is this the termination data?
                        if (data.find(Publication.HEADER_TERMINATE) == 0) and (len(data) >= (len(Publication.HEADER_TERMINATE) + Publication.NONCE_LEN + 32 + 4 + 32 + 32 + 32)):

                            ptr = len(Publication.HEADER_TERMINATE)
                            nonce = data[ptr:ptr + Publication.NONCE_LEN]
                            ptr += Publication.NONCE_LEN
                            stored_nonce_hash = data[ptr:ptr + 32]

                            computed_nonce_hash = hashlib.sha256(Publication.HEADER_TERMINATE + nonce + Publication.NONCE_SALT).digest()
                            if computed_nonce_hash == stored_nonce_hash:
                                termination_data = True

                        # Is this a NOOP?
                        elif (data.find(Publication.HEADER_NOOP) == 0) and (len(data) >= (len(Publication.HEADER_TERMINATE) + Publication.NONCE_LEN + 32)):
                            ptr = len(Publication.HEADER_NOOP)
                            nonce = data[ptr:ptr + Publication.NONCE_LEN]
                            ptr += Publication.NONCE_LEN
                            stored_nonce_hash = data[ptr:ptr + 32]

                            computed_nonce_hash = hashlib.sha256(Publication.HEADER_NOOP + nonce + Publication.NONCE_SALT).digest()
                            if computed_nonce_hash == stored_nonce_hash:
                                noop_data = True
                            else:
                                d('NOOP nonce does not match.')


                        if termination_data:
                            # Skip the header, nonce, and nonce hash.
                            data = data[len(Publication.HEADER_TERMINATE) + Publication.NONCE_LEN + 32:]

                            # Not currently used.
                            reserved = data[0:4]

                            # This is the temporal key.  It is all zeros if
                            # encryption was disabled, or all ones if in
                            # deadman switch mode.
                            temporal_key = data[4:36]

                            # These are not currently used.
                            temporal_iv = data[36:68]
                            temporal_extra = data[68:100]

                            if partial_file.finalize(temporal_key):
                                log("Successfully retrieved file: %s" % partial_file)
                            else:
                                log("Failed to retrieve file: %s" % partial_file)

                            if partial_file.is_deadman_switch_file():
                                log("Deadman switch file retrieved.")


                            partial_file = None

                        elif noop_data: # Don't do anything special.
                            partial_file.add_previous_txid(txid)
                            partial_file.save_state()
                            d('Found NOOP; adding: %s' % txid)
                        else:  # This is continuation data...
                            partial_file.add_previous_txid(txid)

                            if (file_offset == -1) and (len(data) > 4):
                                file_offset = struct.unpack('!I', data[0:4])[0]
                                data = data[4:]

                            bytes_to_write += data

                    else:
                        d('vin_txid not in interesting IDs: %s' % vin_txid)

        # Once all inputs have been processed in this TXID...
        if file_offset >= 0 and bytes_to_write != b'' and \
           partial_file is not None:
            d("Writing %d bytes to offset %d: %s" % (len(bytes_to_write), file_offset, binascii.hexlify(bytes_to_write)))
            partial_file.write_data(bytes_to_write, file_offset)
            partial_file.save_state()


# Save the block info into the lock file.
def save_block_info(lock_fd, block_info):
    lock_fd.seek(0)
    lock_fd.truncate()
    pickle.dump(block_info, lock_fd)
    lock_fd.flush()


# This script must be called as:
#    python3 blockchain_watcher.py rpchostname rpcport rpcuser rpcpass
#       /path/to/output_dir /path/to/log_file.txt block_hash_goes_here [-d]
if __name__ == '__main__':

    rpchost = sys.argv[1]
    rpcport = sys.argv[2]
    rpcuser = sys.argv[3]
    rpcpass = sys.argv[4]
    output_dir = sys.argv[5]
    log_file = sys.argv[6]
    current_block_hash = sys.argv[7]

    rpc_client = RPCClient(rpchost, rpcport, rpcuser, rpcpass)

    if len(sys.argv) == 9 and sys.argv[8] == '-d':
        debug = True

    # Acquire a lock on the output directory.  This prevents blocks from being
    # parsed out of order.  The lock is released in the exit function when
    # this instance terminates.
    lock_file = os.path.join(output_dir, 'lockfile')
    lock_fd = open(lock_file, 'a+b')
    fcntl.lockf(lock_fd, fcntl.LOCK_EX)
    lock_fd.seek(0)

    # Open the log file for appending.  If this fails, terminate.
    try:
        fd = open(log_file, 'a')
    except Exception as e:
        sys.exit(-1)

    # Register the exit function.  This will close the log file handle upon
    # program termination.
    atexit.register(exit_func)

    # Ensure that the output directory is writable.
    if not os.access(output_dir, os.W_OK):
        log("Output directory (%s) is not writeable.  Terminating." % output_dir)
        sys.exit(-1)

    # Check that the partial directory exists.  This is where publications-in-
    # progress will be stored.
    partial_dir = os.path.join(output_dir, 'partial')
    if not os.path.isdir(partial_dir):
        d('Partial directory does not exist (%s).  Creating...' % partial_dir)
        os.mkdir(partial_dir)

    d("Block hash: %s" % current_block_hash)
    current_block = rpc_client.getblock(current_block_hash)
    current_block_num = int(current_block['height'])


    # Well, it turns out that bitcoind/dogecoind does not always call this
    # script with block numbers in their proper order.  The data writing logic
    # handles this just fine, but if a block containing a header comes after
    # a block with its data, this is a problem (similarly if a termination
    # message comes before final data blocks).  So, the code below enforces a
    # strict order.
    #
    # It will track what the last block number processed is, and will process
    # the current one if it is the next in line.  Otherwise, it will save the
    # block number and hash into the lockfile.  Later, when the proper block
    # arrives, the saved subsequent block numbers/hashes are handled.
    #
    # Example: if block #10 was last processed, and block #12 arrives, block
    # 12's hash will be stored in the lockfile and not immediately processed.
    # Later, when #11 arrives, it is handled immediately, then #12 is also
    # processed.

    lock_data = lock_fd.read()

    # If the lockfile is empty, handle this block and initialize the lockfile.
    if len(lock_data) == 0:
        d("Lock data is empty.  Initializing.")
        handle_block(current_block_hash, current_block)
        block_info = {'last_block_num_processed': current_block_num}

    # The lockfile has data, so load it.
    else:
        block_info = pickle.loads(lock_data)

        # Get the number of the last processed block.
        last_block_num_processed = block_info['last_block_num_processed']

        # If the current block number is not the next in line, store the
        # current block number and hash into the lockfile.  We won't process
        # this block right now.
        if (last_block_num_processed + 1) != current_block_num:
            d("Received out-of-order block: %d / %s; last processed: %d" % (current_block_num, current_block_hash, last_block_num_processed))
            block_info[current_block_num] = current_block_hash

        # Otherwise, the current block number is the next in line, so we will
        # process it.
        else:
            d("Handling in-order block: %d / %s" % (current_block_num, current_block_hash))
            handle_block(current_block_hash, current_block)
            block_info['last_block_num_processed'] = current_block_num

            # Check if the next block number is stored.  If so, we can process
            # that now too.  Keep incrementing block numbers until we run out.
            next_block_num = current_block_num + 1
            while next_block_num in block_info:
                next_block_hash = block_info[next_block_num]
                d("Handling next block: %d / %s" % (next_block_num, next_block_hash))
                handle_block(next_block_hash)

                # Since we handled this block, we no longer need to track it.
                del(block_info[next_block_num])

                # Update the latest block we processed.
                block_info['last_block_num_processed'] = next_block_num

                next_block_num = next_block_num + 1

    # Update the lock file with the latest block info.
    save_block_info(lock_fd, block_info)
    exit(0)
