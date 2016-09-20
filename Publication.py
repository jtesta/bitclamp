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

import binascii, hashlib, json, os, math, struct, sys, time

from Utils import *
from TxRecord import *
from RPCClient import *

# Maintains information about a publication campaign.  Maintains state regarding what has been published, and what is left.
class Publication:

    # Flags for the "blockchain" parameter of the constructor.  Specifies what
    # block chain to publish on.
    BLOCKCHAIN_BTC = 1
    BLOCKCHAIN_DOGE = 2

    # Flags for the "network" parameter of the constructor.  Specifies whether
    # to use the real network (mainnet) or the test network.
    NETWORK_MAINNET = 1
    NETWORK_TESTNET = 2

    # The number of confirmations a transaction needs in order to be considered
    # "finalized".  From 1 up to this value, it is only considered "accepted".
    CONFIRMATION_THRESHOLD_BTC = 9
    CONFIRMATION_THRESHOLD_DOGE = 90

    SINGLE_OUTPUT_SIZE = 448

    # The minimum transaction amout.  See https://github.com/bitcoin/bitcoin/blob/master/src/primitives/transaction.h#L161
    DUST_THRESHOLD = 0.00010000 #0.00000546

    # Header bytes to denote the beginning and termination of a publication.
    # These appear first in each transaction payload.
    HEADER_BEGIN     = b'\x00\x11\x22\x33\x44\x55\x66\x77'
    HEADER_TERMINATE = b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff'

    NONCE_LEN = 8
    NONCE_SALT = b'\x09\xf9\x11\x02\x9d\x74\xe3\x5b\xd8\x41\x56\xc5\x63\x56\x88\xc0'


    # Constants for the general flag field in the publication header.
    GENERAL_FLAG_DEADMAN_SWITCH_FILE = 1
    GENERAL_FLAG_DEADMAN_SWITCH_KEY  = 1<<1

    # Constants for the content type field of the start of publication header.
    CONTENT_TYPE_RESERVED    = 0
    CONTENT_TYPE_UNDEFINED   = 1
    CONTENT_TYPE_DOCUMENT    = 2
    CONTENT_TYPE_PICTURE     = 3
    CONTENT_TYPE_SOUND       = 4
    CONTENT_TYPE_VIDEO       = 5
    CONTENT_TYPE_SOURCECODE  = 6
    CONTENT_TYPE_DIGITALSIG  = 7
    CONTENT_TYPE_ARCHIVE     = 8

    CONTENT_TYPE_MAP = {CONTENT_TYPE_RESERVED:'auto', CONTENT_TYPE_UNDEFINED:'undefined', CONTENT_TYPE_DOCUMENT:'document', CONTENT_TYPE_PICTURE:'picture', CONTENT_TYPE_SOUND:'sound', CONTENT_TYPE_VIDEO:'video', CONTENT_TYPE_SOURCECODE:'sourcecode', CONTENT_TYPE_DIGITALSIG:'digitalsignature', CONTENT_TYPE_ARCHIVE:'archive'}


    # Constants for the compression type field of the start of publication
    # header.
    COMPRESSION_TYPE_RESERVED = 0
    COMPRESSION_TYPE_NONE     = 1
    COMPRESSION_TYPE_ZIP      = 2
    COMPRESSION_TYPE_GZIP     = 3
    COMPRESSION_TYPE_BZIP2    = 4
    COMPRESSION_TYPE_XZ       = 5
    COMPRESSION_TYPE_LZMA     = 6
    #COMPRESSION_TYPE_7ZIP     = 7  # The 7z tool sadly won't write to stdout...

    # A map that translates the constants above into their string
    # representations.
    COMPRESSION_TYPE_MAP_STR = {COMPRESSION_TYPE_RESERVED:'auto', COMPRESSION_TYPE_NONE:'none', COMPRESSION_TYPE_ZIP:'zip', COMPRESSION_TYPE_GZIP:'gzip', COMPRESSION_TYPE_BZIP2:'bzip2', COMPRESSION_TYPE_XZ:'xz', COMPRESSION_TYPE_LZMA:'lzma'}

    # A map that returns the corresponding file extensions, given the
    # compression type.
    COMPRESSION_TYPE_MAP_EXT = {COMPRESSION_TYPE_RESERVED:'', COMPRESSION_TYPE_NONE:'', COMPRESSION_TYPE_ZIP:'.zip', COMPRESSION_TYPE_GZIP:'.gz', COMPRESSION_TYPE_BZIP2:'.bz2', COMPRESSION_TYPE_XZ:'.xz', COMPRESSION_TYPE_LZMA:'.lzma'}


    # Types of encryption used.
    ENCRYPTION_TYPE_RESERVED           = 0
    ENCRYPTION_TYPE_NONE               = 1
    ENCRYPTION_TYPE_GPG2_AES256_SHA512 = 2

    ENCRYPTION_TYPE_MAP = {ENCRYPTION_TYPE_RESERVED:'', ENCRYPTION_TYPE_NONE:'none',ENCRYPTION_TYPE_GPG2_AES256_SHA512:'GPG2 AES256 SHA512'}

    # To publish with no file name, set filename to "".  Setting it to None
    # causes it to be set to the filepath.
    def __init__(self, *args):
        if len(args) == 8:
            self.deadman_switch_key_init(args)
            return

        self.rpc_client = args[0]
        self.filepath = args[1]
        self.content_type = args[2]
        self.compression_type = args[3]
        self.filename = args[4]
        self.file_description = args[5]
        self.nocrypto = args[6]
        self.nohash = args[7]
        self.deadman_switch_path = args[8]
        self.blockchain = args[9]
        self.test_or_reg_network = args[10]
        self.num_outputs = args[11]
        self.txfee = args[12]
        self.change_address = args[13]
        self.debug = args[14]
        self.verbose = args[15]


        if len(self.filepath) == 0:
            raise Exception('filepath arg is required!')

        if not os.path.isfile(self.filepath):
            raise Exception("%s is not a regular file!" % self.filepath)

        if self.txfee < 0.0:
            raise Exception("txfee may not be less than 0!: %.8f" % txfee)

        # The general flags field of the publication header.  See GENERAL_FLAG_*
        # constants.
        self.general_flags = 0

        # The encryption key that protects the data as its being published.
        # This is published in the very last block.
        self.temporal_key = b'\x00' * 32

        # Initialization vector for encryption.  Currently reserved for future
        # use.
        self.temporal_iv = b'\x00' * 32

        # Extra data for encryption.  Currently reserved for future use.
        self.temporal_extra = b'\x00' * 32

        # Number of bytes in latest unconfirmed transaction.
        self.bytes_unconfirmed = 0

        # A list of TxRecords that hold transactions that were sent out.  Once
        # a transaction has passed the CONFIRMATION_THRESHOLD_* value, it is
        # removed from this list, as we are certain it will not be reverted.
        self.txrecords = []

        # We generate a new address for each publication.  This is the one
        # legit key used to spend coins sent during each transaction.
        self.address = self.rpc_client.getnewaddress()

        # To sign raw transactions, we need the address's private key.
        self.privkey = self.rpc_client.dumpprivkey(self.address)
        self.d("Private key for publishing: %s" % self.privkey)

        # To create a P2SH address, we need to the raw ECDSA public key from
        # the address.
        self.pubkey = self.rpc_client.validateaddress(self.address)['pubkey']
        self.d("Public key for publishing: %s" % self.pubkey)

        # The number of bytes published per transaction.  This is not valid for
        # the header or termination transactions; only the bulk intermediate
        # ones.  Four bytes are subtracted to account for the file offset.
        self.num_bytes_per_tx = (self.num_outputs * Publication.SINGLE_OUTPUT_SIZE) - 4

        # The amount we have to publish with.  This gets whittled down each
        # transaction by fees.  Any leftover is sent back to the user as change
        # (--change argument).
        self.amount = -1.0

        # Signifies that all bytes in the file were read.
        self.end_of_file_reached = False

        # True when the user sent funds to start the publication process.
        self.received_funds = False

        # Signifies that the terminating message was sent to the change address.
        self.change_sent = False

        # Signifies whether or not this publication is fully complete (meaning
        # that all data was sent and all transactions surpassed the threshold).
        self.complete = False

        # When deadman switch mode is enabled, this tracks whether or not the
        # key has been written to disk yet.
        self.deadman_switch_wrote_key = False

        # If the user did not manually set a content type, we need to figure it
        # out.
        if self.content_type == Publication.CONTENT_TYPE_RESERVED:
            self.content_type = Utils.find_content_type(self.filepath)
            print("Automatic detection of content type is: %s" % Publication.get_content_str(self.content_type))

            if self.content_type == Publication.CONTENT_TYPE_UNDEFINED:
                print("\nError: could not determine content type of file.  You must re-run the program with --content-type and manually set the type.\n")
                sys.exit(-1)


            if self.content_type == Publication.CONTENT_TYPE_ARCHIVE:
                print("\nNote: the 'archive' type is for miscellaneous files.  It is strongly recommended that you manually set the type to document, video, source code, etc. with the --content-type argument, if possible.  This makes your publication more easily searchable & identifiable.\n")

        # The bytes to publish.  This will be the bytes in filepath if no
        # compression is selected.  Otherwise, it will be the compressed
        # bytes returned by Utils.compress_file()
        self.file_bytes = None

        # The user wants no compression used, so just read in the file and
        # leave it as-is.
        if self.compression_type == Publication.COMPRESSION_TYPE_NONE:
            with open(self.filepath, 'rb') as f:
                self.file_bytes = f.read()

        # The user selected automatic detection of optimal compression.
        elif self.compression_type == Publication.COMPRESSION_TYPE_RESERVED:
            self.file_bytes, self.compression_type = Utils.find_optimal_compression(self.filepath, self.v)
        else: # The user selected a specific compression type.
            self.file_bytes = Utils.compress_file(self.filepath, self.compression_type)

        self.encryption_type = Publication.ENCRYPTION_TYPE_NONE

        # If temporal encryption is enabled...
        if not self.nocrypto:
            self.file_bytes, self.temporal_key = Utils.encrypt(self.file_bytes)
            self.encryption_type = Publication.ENCRYPTION_TYPE_GPG2_AES256_SHA512
            self.v('Using encryption type: %s' % Publication.get_encryption_str(self.encryption_type))
        else:
            print("WARNING: temporal encryption is disabled!  Be sure you understand what the implications of this are!")


        self.filesize = len(self.file_bytes)
        if self.filesize == 0:
            raise Exception('Size of file to publish must not be zero!')

        new_extension = Publication.COMPRESSION_TYPE_MAP_EXT[self.compression_type]
        if self.filename != '' and new_extension != '':
            self.filename += new_extension
            print("Automatically adding file extension '%s' to file name to reflect usage of %s compression: %s" % (new_extension, Publication.COMPRESSION_TYPE_MAP_STR[self.compression_type], self.filename))

        # If the user does not want to store the hash of the file in the publication header...
        if self.nohash:
            self.file_hash = b'\x00' * 32
            self.v('Omitting the SHA256 hash from the publication header.')
        else:
            self.file_hash = hashlib.sha256(self.file_bytes).digest()
            self.d("SHA256 of file bytes: %s" % binascii.hexlify(self.file_hash).decode('ascii'))

        # If we are in deadman switch publish mode, set the flag in the general headers.
        if self.deadman_switch_path is not None:
            self.general_flags |= Publication.GENERAL_FLAG_DEADMAN_SWITCH_FILE
            self.d("Setting GENERAL_FLAG_DEADMAN_SWITCH_FILE.")

        # For resuming publication after interruptions.
        self.state_file = "bitclamp_state_" + os.path.basename(self.filepath) + '_' + time.strftime("%Y-%m-%d_%H-%M") + '.state'

        # Set a flag that denotes we are NOT trying to publish a deadman switch key (see constructor below for that code).
        self.deadman_switch_key_publish_mode = False


    # Special constructor for when publishing a deadman switch key.
    def deadman_switch_key_init(self, args): #rpc_client, key_file, blockchain, test_or_reg_network, txfee, change_address, debug, verbose):
        self.rpc_client = args[0]
        self.filepath = args[1]
        self.blockchain = args[2]
        self.test_or_reg_network = args[3]
        self.txfee = args[4]
        self.change_address = args[5]
        self.debug = args[6]
        self.verbose = args[7]

        if not os.path.isfile(self.filepath):
            raise Exception("%s is not a regular file!" % self.filepath)

        if self.txfee < 0.0:
            raise Exception("txfee may not be less than 0!: %.8f" % txfee)

        key_lines = None
        with open(self.filepath, 'r') as f:
            key_lines = f.readlines()

        # Ensure that we read exactly four lines.
        if len(key_lines) != 4:
            raise Exception("Key file does not have 4 lines (" + len(key_lines) + ").  It appears to be corrupted.")

        # Decode each of the four lines and add them to the bytes to publish.
        self.file_bytes = binascii.unhexlify(key_lines[0].strip())
        self.file_bytes += binascii.unhexlify(key_lines[1].strip())
        self.file_bytes += binascii.unhexlify(key_lines[2].strip())
        self.file_bytes += binascii.unhexlify(key_lines[3].strip())
        self.filesize = len(self.file_bytes)

        # Ensure that we read exactly 128 bytes.
        if self.filesize != 128:
            raise Exception("Decoded key file does not yield 128 bytes!.  It appears to be corrupted.")

        self.num_outputs = 1
        self.num_bytes_per_tx = Publication.SINGLE_OUTPUT_SIZE
        self.general_flags = Publication.GENERAL_FLAG_DEADMAN_SWITCH_KEY
        self.content_type = Publication.CONTENT_TYPE_UNDEFINED
        self.compression_type = Publication.COMPRESSION_TYPE_NONE
        self.encryption_type = Publication.ENCRYPTION_TYPE_NONE
        self.file_hash = b'\x00' * 32
        self.filename = ''
        self.file_description = ''
        self.txrecords = []
        self.bytes_unconfirmed = 0
        self.end_of_file_reached = False
        self.temporal_key = None
        self.temporal_iv = None
        self.temporal_extra = None
        self.deadman_switch_path = None

        # We generate a new address for each publication.  This is the one
        # legit key used to spend coins sent during each transaction.
        self.address = self.rpc_client.getnewaddress()

        # To sign raw transactions, we need the address's private key.
        self.privkey = self.rpc_client.dumpprivkey(self.address)
        self.d("Private key for publishing: %s" % self.privkey)

        # To create a P2SH address, we need to the raw ECDSA public key from
        # the address.
        self.pubkey = self.rpc_client.validateaddress(self.address)['pubkey']
        self.d("Public key for publishing: %s" % self.pubkey)

        # Set a flag that denotes we are trying to publish a deadman switch key.
        self.deadman_switch_key_publish_mode = True


    # Prints a message when debugging is enabled.
    def d(self, s):
        if self.debug:
            print(s)


    # Prints a message when verbosity is enabled.
    def v(self, s):
        if self.verbose:
            print(s)


    def set_amount(self, amount):
        self.amount = amount


    # Return the number of confirmations a transaction needs in order to be
    # considered finalized.
    def get_confirmation_threshold(self):
        return Publication.CONFIRMATION_THRESHOLD_BTC if self.blockchain == Publication.BLOCKCHAIN_BTC else Publication.CONFIRMATION_THRESHOLD_DOGE


    # Returns "BTC" or "DOGE", depending on which chain we are publishing on.
    def get_currency_str(self):
        return "BTC" if self.blockchain == Publication.BLOCKCHAIN_BTC else "DOGE"


    # Returns the amount that each TX output should have, excluding the fee
    # (since vin - vout = fee).
    def get_tx_output_amount(self, nbytes, noutputs):
        prev_amount = self.amount

        kb = nbytes / 1024
        if self.blockchain == Publication.BLOCKCHAIN_DOGE:
            kb = math.ceil(kb)

        # The fee for this upcoming transaction is the number of bytes we're
        # about to send, in KB, times the per-KB fee.
        fee = kb * self.txfee

        self.amount = self.amount - fee
        ret = self.amount / noutputs

        # To account for any rounding, multiply the return value by the number
        # of outputs.  We may lose an extra satoshi to the tx fee.
        self.amount = ret * noutputs

        self.d("get_tx_output_amount(%d, %d): fee per KB: %.8f; previous amount: %.8f; fee for %d bytes: %.8f; new amount = previous amount (%.8f) - fee (%.8f) = %.8f; Returning: %.8f / %d = %.8f" % (nbytes, noutputs, self.txfee, prev_amount, nbytes, fee, prev_amount, fee, self.amount, self.amount, noutputs, ret))
        return ret


    def get_file_position(self):
        return self.bytes_unconfirmed


    def add_txrecord(self, txrecord):
        self.txrecords.append(txrecord)


    def update_unconfirmed_bytes(self, num_bytes):
        self.bytes_unconfirmed += num_bytes
        self.d("update_unconfirmed_bytes(%d); count: %d" % (num_bytes, self.bytes_unconfirmed))


    # Return an estimate as to how long the specified number of transactions
    # will take.
    @staticmethod
    def get_time_estimate(num_transactions, chain):
        mins = num_transactions
        if chain == Publication.BLOCKCHAIN_BTC:
            mins = mins * 10

        hours = 0
        days = 0
        ret = '%d minutes' % mins
        if mins >= 60:
            hours = int(mins / 60)
            mins = mins % 60
            ret = '%d hours, %d minutes' % (hours, mins)

        if hours >= 24:
            days = int(hours / 24)
            hours = hours % 24
            ret = '%d days, %d hours, %d minutes' % (days, hours, mins)

        if days > 100:
            ret = 'a long freaking time (%s)' % ret

        return ret


    def make_p2sh_address(self, script_bytes):
        h = hashlib.new('ripemd160')
        h.update(hashlib.sha256(script_bytes).digest())
        hash160 = h.digest()

        version = b'\x05'
        if self.blockchain == Publication.BLOCKCHAIN_DOGE:
            version = b'\x16' # 22, from src/chainparams.cpp

        if self.test_or_reg_network:
            version = b'\xc4' # 196, for testnet

        tag = hashlib.sha256(hashlib.sha256(version + hash160).digest()).digest()[:4]
        return Utils.base58_encode(version + hash160 + tag)


    def __str__(self):
        s = "\n\n"
        for txrecord in self.txrecords:
            s += "\t" + str(txrecord) + "\n"
        return "Publication:\n\tFile path: %s\n\tFilename: %s\n\tFile size: %d\n\tTemporal key: %s\n\tBytes unconfirmed: %d%s" % (self.filepath, self.filename, self.filesize, binascii.hexlify(self.temporal_key).decode('ascii'), self.bytes_unconfirmed, s)


    # Argument must be of size 'single_output_size'
    def make_redeem_script(self, byte_block):
        byte_block_len = len(byte_block)

        # If the block is not aligned to 32 bytes, then we need to pad it with
        # zeros.
        mod = byte_block_len % 32
        if mod != 0:
            self.d("Adding %d bytes of padding to block of length %d." % (32 - mod, byte_block_len))
            byte_block += b'\x00' * (32 - mod)

            # Update the length since we just modified the block.
            byte_block_len = len(byte_block)


        num_keys = int(byte_block_len / 32)
        if num_keys > 14:
            print("make_redeem_script(): no more than 14 keys may be present: %d" % num_keys)
            sys.exit(-1)

        # Convert the number of keys to the appropriate OP_* value to specify
        # how many total keys we are presenting (+1 is for the legit key).
        # For example, if one data key is present, then 80 + 1 + 1 = 82 = 0x52
        # = OP_2 (which is correct, since there is also one legit key).
        op_num_keys = bytes([80 + num_keys + 1])
        self.d("op_num_keys = %s; num_keys = %d; byte_block: %d" % (op_num_keys, num_keys, len(byte_block)))

        # 0x51 = OP_1 (meaning that at least one key/signature must be
        # presented.)
        redeem_script = b'\x51'

        # Set the first key to be the real public key we will use to later
        # spend the funds.
        redeem_script += b'\x21' + binascii.unhexlify(self.pubkey)

        start_pos = 0
        end_pos = 32
        for i in range(0, num_keys):
            # 0x21 = Push next 0x21 bytes to stack
            # 0x02 = Prefix for public key
            redeem_script += b'\x21\x02' + byte_block[start_pos:end_pos]
            start_pos += 32
            end_pos += 32

        # 0xae = OP_CHECKMULTISIG (check that one key & signature out of the 15
        # is valid)
        redeem_script += op_num_keys + b'\xae'


        return redeem_script, self.make_p2sh_address(redeem_script)


    # If we are in deadman switch mode, write out the encryption key, if we
    # didn't already.
    def store_deadman_switch_key(self, next_txid):

        # If we are not in deadman switch mode, or if we already wrote out the
        # key, just return without doing anything.
        if self.deadman_switch_path is None or \
           self.deadman_switch_wrote_key is True:
            return

        with open(self.deadman_switch_path, 'w') as f:
            f.write(next_txid)
            f.write("\n")
            f.write(binascii.hexlify(self.temporal_key).decode('ascii'))
            f.write("\n")
            f.write(binascii.hexlify(self.temporal_iv).decode('ascii'))
            f.write("\n")
            f.write(binascii.hexlify(self.temporal_extra).decode('ascii'))

        self.deadman_switch_wrote_key = True


    # Begins the publication process.  Returns the P2SH address that the user
    # must send funds to.
    def begin(self):

        self.v('Beginning to publish %s using %d outputs per transaction / %d bytes per transaction.' % (self.filepath, self.num_outputs, self.num_bytes_per_tx))

        num_transactions = math.ceil(self.filesize / self.num_bytes_per_tx)
        self.v('%s is %d bytes long.  Publication will take %d transactions, which, under optimal conditions, will take %s.' % (self.filepath, self.filesize, num_transactions, Publication.get_time_estimate(num_transactions, self.blockchain)))

        # 8 bytes to denote the start of a file
        # 8 bytes for nonce
        # 32 bytes for nonce hash
        # 2 bytes reserved (0x0000)
        # 1 byte for general flags
        # 1 byte for encryption type
        # 1 byte for the content type
        # 1 byte for the compression type
        # 4 bytes for the file size
        # 32 bytes for the SHA256 hash of the file
        # 1 byte for the filename length (N)
        # 1 byte for the description length (M)
        # N bytes for the filename (up to 128)
        # M bytes for the description (up to 128)
        nonce = os.urandom(Publication.NONCE_LEN)
        nonce_hash = hashlib.sha256(Publication.NONCE_SALT + nonce).digest()
        header_bytes = \
            Publication.HEADER_BEGIN + \
            nonce + \
            nonce_hash + \
            b'\x00\x00' + \
            struct.pack('!B', self.general_flags) + \
            struct.pack('!B', self.encryption_type) + \
            struct.pack('!B', self.content_type) + \
            struct.pack('!B', self.compression_type) + \
            struct.pack('!I', self.filesize) + \
            self.file_hash + \
            struct.pack('!B', len(self.filename)) + \
            struct.pack('!B', len(self.file_description)) + \
            self.filename.encode('utf-8') + \
            self.file_description.encode('utf-8')

        self.d("Header bytes: %s" % binascii.hexlify(header_bytes).decode('ascii'))

        # Read the first bytes out of the file.  Since we have to include a
        # header, subtract those bytes from the single output size.
        bytes_to_read = min(Publication.SINGLE_OUTPUT_SIZE - len(header_bytes), self.filesize)
        first_block = self.file_bytes[0:bytes_to_read]

        # Create the redeem script and P2SH address for the first transaction.
        redeem_script, p2sh_address = self.make_redeem_script(header_bytes + first_block)

        txrecord = TxRecord([redeem_script], [p2sh_address])

        # Estimate the cost to publish this file, then tell the user where &
        # how much to send.
        cost, unused1, unused2, unused3, unused4 = Utils.get_estimate(self.rpc_client, self.filepath, self.blockchain, self.num_outputs, self.txfee)
        print("To begin publication, send %.8f %s to %s" % (cost + 0.00000001, self.get_currency_str(), p2sh_address))
        self.d("$CLI sendtoaddress %s %.8f; $CLI generate 1; sleep 2; $CLI generate 1" % (p2sh_address, cost+0.00000001))

        # Wait for a transaction to get at least 1 confirmation which paid us
        # to begin.
        if not self.wait_for_confirmation(txrecord, p2sh_address):
            print("wait_for_confirmation() failed!")

        print("Received funds.  Beginning publication...")
        self.received_funds = True

        self.update_unconfirmed_bytes(bytes_to_read)
        self.add_txrecord(txrecord)

        # Check that the amount sent by the user meets the minimum.
        sent_amount = 0.0
        for value in txrecord.get_values():
            sent_amount += float(value)
        if sent_amount < cost:
            print("Warning: only %.8f was sent instead of the minimum (%.8f)!" % (sent_amount, cost))
        self.set_amount(sent_amount)

        # TXID, vout_nums point to user's transaction to script.  TxRecord has
        # redeem script for next transaction.
        continue_flag = True

        # If we are trying to publish a deadman switch key, set end_of_file_reached to True in order to skip the
        # termination message, which isn't necessary.
        if self.deadman_switch_key_publish_mode:
            self.end_of_file_reached = True

        while continue_flag:
            self.d("Sending redeemscripts in: %s" % txrecord)
            next_txrecord = self.resume(txrecord)
            self.d("Next record: %s" % next_txrecord)
            self.d("Waiting for next txid to be confirmed: %s" % next_txrecord.get_txid())
            if not self.wait_for_confirmation(next_txrecord, None):
                print("wait_for_confirmation() failed!")

            print("Sent data block was confirmed.  Sending next block...")

            txrecord = next_txrecord

            if self.change_sent is True:
                next_txrecord.set_last_record()
                continue_flag = False


        print("\nPublication complete!  Waiting for the transactions to surpass the confirmation threshold.  This phase is optional.")

        # Keep waiting until all TxRecords have surpassed the confirmation
        # threshold.
        while len(self.txrecords) > 0:
            if not self.wait_for_confirmation(next_txrecord, None):
                print("wait_for_confirmation() failed!")
            print("%d transactions awaiting full confirmation..." % len(self.txrecords))

            self.d("\nTxRecords:")
            for txrecord in self.txrecords:
                self.d("\t%s" % txrecord)

        print("All transactions fully confirmed.")


    def resume(self, txrecord):

        redeem_scripts = []
        p2sh_addresses = []

        # The number of outputs might end up being less than the user-defined
        # amount if the bytes left to publish do not align to a boundary.
        noutputs = self.num_outputs

        file_pos = self.get_file_position()
        bytes_to_read = 0
        if (file_pos >= self.filesize) and (self.end_of_file_reached is False):
            self.end_of_file_reached = True
            self.d("Reached end of file.  Finalizing publication...")

            key = self.temporal_key
            iv = self.temporal_iv
            extra = self.temporal_extra

            # If the deadman switch is enabled, overwrite the key information.
            if self.deadman_switch_path is not None:
                key = b'\xff' * 32
                iv = b'\xff' * 32
                extra = b'\xff' * 32

            # 8 bytes to denote the end of the file
            # 4 bytes to denote the number of parallel transactions
            # 4 reserved bytes
            # 32 bytes for the temporal encryption key
            # 32 bytes for the temporal IV (currently not used)
            # 32 bytes for extra encryption data (currently not used)
            header_termination_bytes = Publication.HEADER_TERMINATE + \
                struct.pack('!I', 1) + \
                b'\x00\x00\x00\x00' + \
                key + \
                iv + \
                extra

            self.d("\nTermination bytes: %s" % binascii.hexlify(header_termination_bytes).decode('ascii'))
            
            redeem_script, p2sh_address = self.make_redeem_script(header_termination_bytes)
            redeem_scripts.append(redeem_script)
            p2sh_addresses.append(p2sh_address)

            noutputs = 1

        elif self.end_of_file_reached is True:
            self.d("Sending terminating message to change address...")
            p2sh_addresses.append(self.change_address)
            self.change_sent = True

            noutputs = 1
        else:

            self.d("Seeking to file position %d." % self.get_file_position())

            # Calculate the number of bytes to publish now.  This is set to
            # self.num_bytes_per_tx, unless the remaining bytes is smaller.
            bytes_to_read = self.num_bytes_per_tx
            if file_pos + bytes_to_read > self.filesize:
                bytes_to_read = self.filesize - file_pos

            file_offset = struct.pack('!I', file_pos)

            next_block = file_offset + self.file_bytes[file_pos:file_pos + bytes_to_read]
            self.d("Next block: %s" % binascii.hexlify(next_block).decode('ascii'))

            next_block_len = len(next_block)
            noutputs = int(min(self.num_outputs, math.ceil(next_block_len / Publication.SINGLE_OUTPUT_SIZE)))
            if noutputs != self.num_outputs:
                self.d("File does not align to %d boundary (%d); using %d outputs instead of %d." % (Publication.SINGLE_OUTPUT_SIZE, next_block_len, noutputs, self.num_outputs))

            # Create output addresses & corresponding redeemscripts
            start_pos = 0
            end_pos = Publication.SINGLE_OUTPUT_SIZE
            for i in range(0, noutputs):
                redeem_script, p2sh_address = self.make_redeem_script(next_block[start_pos:end_pos])
                redeem_scripts.append(redeem_script)
                p2sh_addresses.append(p2sh_address)

                start_pos += Publication.SINGLE_OUTPUT_SIZE
                end_pos += Publication.SINGLE_OUTPUT_SIZE


        next_txrecord = TxRecord(redeem_scripts, p2sh_addresses)
        self.add_txrecord(next_txrecord)



        signed_raw_tx_hex = self.create_and_sign_tx(txrecord, redeem_scripts, p2sh_addresses, 0.00000001)
        tx_len = len(signed_raw_tx_hex) / 2
        self.d("Length of signed message: %d" % tx_len)

        amount = self.get_tx_output_amount(tx_len, noutputs)


        # If we reached the end of the file, we send the final amount to one
        # single P2SH address
        if self.change_sent:
            self.d("Sending %.8f to change address." % amount)
        else:
            self.d("Sending %.8f per output." % amount)

        signed_raw_tx_hex = self.create_and_sign_tx(txrecord, redeem_scripts, p2sh_addresses, amount)
        self.d("Signed raw_tx: %s" % signed_raw_tx_hex)

        next_txid = self.rpc_client.sendrawtransaction(signed_raw_tx_hex)
        if len(next_txid) == 64:
            self.d("Sent!: %s" % next_txid)
            next_txrecord.set_txid(next_txid)
            self.update_unconfirmed_bytes(bytes_to_read)

            # If we are in deadman switch mode, and did not yet write out the
            # key, do that now.
            self.store_deadman_switch_key(next_txid)

            return next_txrecord
        else:
            print("Failed: %s" % next_txid)
            return None


    def create_and_sign_tx(self, txrecord, redeem_scripts, p2sh_addresses, amount):

        txid = txrecord.txid

        inputs = []
        for vout_num in txrecord.get_vout_nums():
            input = {}
            input['txid'] = txid
            input['vout'] = vout_num
            inputs.append(input)

        # This must be a string instead of dictionary, because order is
        # extremely important (a dictionary often changes the order
        # automatically).  If this is out of order, then file data is
        # transmitted incorrectly.
        outputs_str = '{'
        for p2sh_address in p2sh_addresses:
            outputs_str += "\"%s\": %.8f," % (p2sh_address, amount)
        outputs_str = outputs_str[:-1] + '}'

        unsigned_raw_tx = self.rpc_client.createrawtransaction(json.dumps(inputs), outputs_str)

        output_scripts = txrecord.get_output_scripts()
        vout_nums = txrecord.get_vout_nums()
        stuffs = []

        if len(vout_nums) != len(txrecord.redeem_scripts):
            print("Len mismatch: %d, %d" % (len(vout_nums), len(txrecord.redeem_scripts)))


        for i in range(0, len(txrecord.redeem_scripts)):
            stuff = {}
            stuff['txid'] = txid
            stuff['vout'] = vout_nums[i]
            stuff['scriptPubKey'] = output_scripts[i]
            stuff['redeemScript'] = binascii.hexlify(txrecord.redeem_scripts[i]).decode('ascii')
            stuffs.append(stuff)

        signed_raw_tx = self.rpc_client.signrawtransaction(unsigned_raw_tx, stuffs, self.privkey)
        return signed_raw_tx['hex']



    # Wait for a transaction to get at least 1 confirmation.  If the TXID is
    # given, then that specific transaction is waited for.  Otherwise, all
    # transactions in new blocks are examined for funds to be sent to the
    # recipient_address.
    def wait_for_confirmation(self, txrecord, recipient_address):
        txid = txrecord.get_txid()

        continue_flag = True
        best_block_hash = self.rpc_client.getbestblockhash()

        while continue_flag:
            time.sleep(1)

            block_hash = self.rpc_client.getbestblockhash()

            # If we havent found a new block, then loop back to the top and
            # sleep.
            if block_hash == best_block_hash:
                continue

            self.d("Detected new block.  Block hash: %s" % block_hash)
            best_block_hash = block_hash

            # Update the confirmation count for all TxRecords we are currently
            # maintaining.
            self.update_confirmations()

            # If we are looking for a specific TXID...
            if txid is not None:
                # Try to get the JSON of the raw transaction.
                rawtransaction = self.rpc_client.getrawtransaction(txid, 1)

                # Check if it has a "confirmations" field.  If not, this TXID
                # is still unconfirmed.
                if 'confirmations' in rawtransaction:
                    ret_confirmations = int(rawtransaction['confirmations'])
                    if ret_confirmations > 0:
                        vouts = rawtransaction['vout']
                        for vout in vouts:
                            txrecord.add_output_script(vout['scriptPubKey']['hex'])
                            txrecord.add_vout_num(int(vout['n']))
                            txrecord.add_value(vout['value'])

                        return True

            # If we are looking for funds sent to an address.
            else:

                # Get the latest block, which includes all the TXIDs.
                t1 = time.time()

                block_txs = self.rpc_client.getblock(best_block_hash)['tx']
                self.d("Parsed getblock(%s) in %d seconds." % (best_block_hash, int(time.time() - t1)))

                t1 = time.time()
                # Loop through all the TXIDs in this block, and parse them all.
                for tx in block_txs:
                    try:
                        rawtransaction = self.rpc_client.getrawtransaction(tx, 1)
                    except Exception as e:
                        print("Error while trying to retrieve TXID %s." % tx)
                        continue

                    ret_confirmations = int(rawtransaction['confirmations'])
                    vouts = rawtransaction['vout']
                    for vout in vouts:

                        if (vout['scriptPubKey']['type'] == 'scripthash') and (recipient_address in vout['scriptPubKey']['addresses']):
                            txrecord.set_txid(tx)
                            txrecord.add_output_script(vout['scriptPubKey']['hex'])
                            txrecord.add_vout_num(int(vout['n']))
                            txrecord.add_value(vout['value'])
                            continue_flag = False
                            break

                    if continue_flag == False:
                        break

                print("Parsed all TXIDs in block in %d seconds." % int(time.time() - t1))

        return True


    # Updates the confirmation count for all tracked transactions.
    def update_confirmations(self, update_vout = False):

        # Update all the confirmation counts for all TxRecords in the list.
        for txrecord in self.txrecords:
            txid = txrecord.get_txid()
            if txid is not None:

                rawtransaction = self.rpc_client.getrawtransaction(txid, 1)
                if 'confirmations' in rawtransaction:
                    confirmations = int(rawtransaction['confirmations'])
                    txrecord.set_confirmations(confirmations)

                if update_vout and 'vout' in rawtransaction and len(txrecord.get_output_scripts()) == 0 and len(txrecord.get_vout_nums()) == 0 and len(txrecord.get_values()) == 0:
                    print("LENS: %d %d %d" % (len(txrecord.get_output_scripts()), len(txrecord.get_vout_nums()), len(txrecord.get_values())))
                    vouts = rawtransaction['vout']
                    for vout in vouts:
                        txrecord.add_output_script(vout['scriptPubKey']['hex'])
                        txrecord.add_vout_num(int(vout['n']))
                        txrecord.add_value(vout['value'])
                            

        confirmation_threshold = self.get_confirmation_threshold()

        # Go through the list again now that all confirmation counts are
        # updated.  If the current TxRecord is passed the threshold as well as
        # the next one, remove the current TxRecord.  The next record matters
        # because to re-transmit a transaction, information from the previous
        # TxRecord (its redeemscripts) are needed.
        i = 0
        while i < len(self.txrecords) - 1:
        #for i in range(0, len(self.txrecords) - 1):
            #print("Len: %d" % len(self.txrecords))
            #print("i: %d" % i)
            txrecord_cur = self.txrecords[i]
            txrecord_next = self.txrecords[i + 1]

            if (txrecord_cur.get_confirmations() > confirmation_threshold) and (txrecord_next.get_confirmations() > confirmation_threshold):
                self.d("TXID %s has surpassed the confirmation threshold (%d)." % (txid, confirmation_threshold))
                self.txrecords.remove(txrecord_cur)
            else:
                i += 1

        if len(self.txrecords) == 1:
            txrecord = self.txrecords[0]
            if txrecord.is_last_record() and (txrecord.get_confirmations() > confirmation_threshold):
                self.d("Last TXID (%s) surpassed the confirmation threshold." % txrecord.get_txid())
                self.txrecords = []
                self.complete = True


    # Given a CONTENT_TYPE_ constant, return its string representation.
    @staticmethod
    def get_content_str(content_type):
        if content_type not in Publication.CONTENT_TYPE_MAP:
            return 'unknown'

        return Publication.CONTENT_TYPE_MAP[content_type]


    # Given a COMPRESSION_TYPE_ constant, return its string representation.
    @staticmethod
    def get_compression_str(compression_type):
        if compression_type not in Publication.COMPRESSION_TYPE_MAP_STR:
            return 'unknown'

        return Publication.COMPRESSION_TYPE_MAP_STR[compression_type]


    # Given an ENCRYPTION_TYPE_ constant, return its string representation.
    @staticmethod
    def get_encryption_str(encryption_type):
        if encryption_type not in Publication.ENCRYPTION_TYPE_MAP:
            return 'unknown'

        return Publication.ENCRYPTION_TYPE_MAP[encryption_type]
