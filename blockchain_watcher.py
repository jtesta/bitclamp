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
from BlockParser import *
from RPCClient import *
from Utils import *

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


# Save the block info into the lock file.
def save_block_info(lock_fd, block_info):
    lock_fd.seek(0)
    lock_fd.truncate()
    pickle.dump(block_info, lock_fd)
    lock_fd.flush()


# This script must be called as:
#    python3 blockchain_watcher.py [btc | doge] /path/to/output_dir
#       /path/to/log_file.txt block_hash_goes_here [-d]
if __name__ == '__main__':

    chain = sys.argv[1]
    output_dir = sys.argv[2]
    log_file = sys.argv[3]
    current_block_hash = sys.argv[4]

    if not ((chain == 'btc') or (chain == 'doge')):
        print("ERROR: first argument must be 'btc' or 'doge': %s" % chain)
        exit(-1)

    if len(sys.argv) == 6 and sys.argv[5] == '-d':
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

    # Get an RPCClient to work with.
    rpc_client = RPCClient.init_from_config_file(chain)

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

    # Initialize the BlockParser with the debugging & logging functions,
    # RPCClient, output directory, and partial directory.
    BlockParser.init(d, log, rpc_client, output_dir, partial_dir)

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
        BlockParser.parse_block(current_block_num, current_block_hash, current_block)
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
            BlockParser.parse_block(current_block_num, current_block_hash, current_block)
            block_info['last_block_num_processed'] = current_block_num

            # Check if the next block number is stored.  If so, we can process
            # that now too.  Keep incrementing block numbers until we run out.
            next_block_num = current_block_num + 1
            while next_block_num in block_info:
                next_block_hash = block_info[next_block_num]
                d("Handling next block: %d / %s" % (next_block_num, next_block_hash))
                BlockParser.parse_block(next_block_num, next_block_hash)

                # Since we handled this block, we no longer need to track it.
                del(block_info[next_block_num])

                # Update the latest block we processed.
                block_info['last_block_num_processed'] = next_block_num

                next_block_num = next_block_num + 1

    # Update the lock file with the latest block info.
    save_block_info(lock_fd, block_info)
    exit(0)
