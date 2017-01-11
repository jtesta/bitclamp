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

import binascii, fcntl, hashlib, json, os, math, struct, sys, time

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
    HEADER_NOOP      = b'\x12\x23\x34\x45\x56\x67\x78\x89'
    HEADER_TERMINATE = b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff'

    NONCE_LEN = 16
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

        # If only 9 arguments are present, the constructor for publishing
        # deadman switch keys should be used instead.
        if len(args) == 10:
            self.deadman_switch_key_init(args)
            return

        self.rpc_client = args[0]
        self.block_listener = args[1]
        self.filepath = args[2]
        self.content_type = args[3]
        self.compression_type = args[4]
        self.filename = args[5]
        self.file_description = args[6]
        self.nocrypto = args[7]
        self.nohash = args[8]
        self.deadman_switch_path = args[9]
        self.blockchain = args[10]
        self.test_or_reg_network = args[11]
        self.num_outputs = args[12]
        self.num_transactions = args[13]
        self.txfee = args[14]
        self.change_address = args[15]
        self.debug = args[16]
        self.verbose = args[17]

        # If not None, this is the filesystem path were the initial publication
        # address and amount should be placed.  This is only used during unit
        # testing.
        self.unittest_publication_address = args[18]

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

        # Initialize the txrecords data structure.
        self.init_txrecords_and_ending_noop_array()

        # Set to True when the publication termination message has been sent.
        self.termination_record_sent = False

        # We generate a new address for each publication.  This is the one
        # legit key used to spend coins sent during each transaction.
        self.address = self.rpc_client.getnewaddress()

        # To sign raw transactions, we need the address's private key.
        self.privkey = self.rpc_client.dumpprivkey(self.address)

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
            print("Automatic detection of content type is: %s" % Publication.get_content_type_str(self.content_type))

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

        # If the user does not want to store the hash of the file in the
        # publication header...
        if self.nohash:
            self.file_hash = b'\x00' * 32
            self.v('Omitting the SHA256 hash from the publication header.')
        else:
            self.file_hash = hashlib.sha256(self.file_bytes).digest()
            self.d("SHA256 of file bytes: %s" % binascii.hexlify(self.file_hash).decode('ascii'))

        # If we are in deadman switch publish mode, set the flag in the general
        # headers.
        if self.deadman_switch_path is not None:
            self.general_flags |= Publication.GENERAL_FLAG_DEADMAN_SWITCH_FILE
            self.d("Setting GENERAL_FLAG_DEADMAN_SWITCH_FILE.")

        # For resuming publication after interruptions.
        self.state_file = os.path.join(os.getcwd(), "bitclamp_state_" + os.path.basename(self.filepath) + '_' + time.strftime("%Y-%m-%d_%H-%M") + '.state')

        # Set a flag that denotes we are NOT trying to publish a deadman switch
        # key (see constructor below for that code).
        self.deadman_switch_key_publish_mode = False


    # Special constructor for when publishing a deadman switch key.
    def deadman_switch_key_init(self, args):
        self.rpc_client = args[0]
        self.block_listener = args[1]
        self.filepath = args[2]
        self.blockchain = args[3]
        self.test_or_reg_network = args[4]
        self.txfee = args[5]
        self.change_address = args[6]
        self.debug = args[7]
        self.verbose = args[8]
        self.unittest_publication_address = args[9]

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
        self.num_transactions = 1
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
        self.termination_record_sent = False
        self.change_sent = False

        self.init_txrecords_and_ending_noop_array()

        # We generate a new address for each publication.  This is the one
        # legit key used to spend coins sent during each transaction.
        self.address = self.rpc_client.getnewaddress()

        # To sign raw transactions, we need the address's private key.
        self.privkey = self.rpc_client.dumpprivkey(self.address)

        # To create a P2SH address, we need to the raw ECDSA public key from
        # the address.
        self.pubkey = self.rpc_client.validateaddress(self.address)['pubkey']
        self.d("Public key for publishing: %s" % self.pubkey)

        # Set a flag that denotes we are trying to publish a deadman switch key.
        self.deadman_switch_key_publish_mode = True


    # When serializing this object, exclude the BlockListener, as it contains
    # a socket (among other things not worth keeping).  Also exclude the
    # RPCClient, as it should be re-created upon restoration in case
    # credentials are changed.
    def __getstate__(self):
        state = self.__dict__.copy()
        del state['block_listener']
        del state['rpc_client']
        del state['unittest_publication_address']
        return state


    # When restoring a serialized object, set block_listener to None; the
    # set_block_listener() method should be used once the listener is
    # available.
    def __setstate__(self, state):
        self.__dict__.update(state)
        self.block_listener = None
        self.rpc_client = None
        self.unittest_publication_address = None


    # Prints a message when debugging is enabled.
    def d(self, s):
        if self.debug:
            print(s)


    # Prints a message when verbosity is enabled.
    def v(self, s):
        if self.verbose:
            print(s)


    # Return the number of confirmations a transaction needs in order to be
    # considered finalized.
    def get_confirmation_threshold(self):
        return Publication.CONFIRMATION_THRESHOLD_BTC if self.blockchain == Publication.BLOCKCHAIN_BTC else Publication.CONFIRMATION_THRESHOLD_DOGE


    # Returns "BTC" or "DOGE", depending on which chain we are publishing on.
    def get_currency_str(self):
        return "BTC" if self.blockchain == Publication.BLOCKCHAIN_BTC else "DOGE"


    # Returns the amount that each TX output should have, excluding the fee
    # (since vin - vout = fee).
    @staticmethod
    def get_tx_output_amount(d, chain, total_amount, txfee, nbytes, noutputs, recurse_level=0):
        kb = nbytes / 1024
        if chain == Publication.BLOCKCHAIN_DOGE:
            kb = math.ceil(kb)

        # The fee for this upcoming transaction is the number of bytes we're
        # about to send, in KB, times the per-KB fee.
        fee = kb * txfee

        # In a test environment, the Dogecoin daemon was observed to randomly
        # reject a transaction because of 'insufficient priority'.  In that
        # case, we will recurse and re-calculate the fee amount.  We will
        # bump up an entire transaction's fee by 1 or 2 DOGE depending on how
        # many consecutive failures we've had.
        if (chain == Publication.BLOCKCHAIN_DOGE):
            if recurse_level > 1:
                fee += 2
            elif recurse_level > 0:
                fee += 1

        per_output_amount = (total_amount - fee) / noutputs

        # To account for any rounding, multiply the return value by the number
        # of outputs.  We may lose an extra satoshi to the tx fee.
        next_total_amount = per_output_amount * noutputs

        d("get_tx_output_amount(total_amount: %.8f, txfee: %.8f, nbytes: %d, noutputs: %d); fee = KB (%f) * txfee (%.8f) = %.8f; Per-output amount = (total_amount (%.8f) - fee (%.8f)) / num_outputs (%d) = %.8f; next total_amount: %.8f" % (total_amount, txfee, nbytes, noutputs, kb, txfee, fee, total_amount, fee, noutputs, per_output_amount, next_total_amount))
        return next_total_amount, per_output_amount


    # Returns the position in the file up to which it was already read.
    def get_file_position(self):
        return self.bytes_unconfirmed


    # Adds a new TxRecord as a child to the specified parent.
    def add_txrecord(self, parent_txrecord, new_txrecord):
        for i in range(0, self.num_transactions):
            if self.txrecords[i][-1] == parent_txrecord:
                self.txrecords[i].append(new_txrecord)


    # Updates the file position.
    def update_unconfirmed_bytes(self, num_bytes):
        self.bytes_unconfirmed += num_bytes
        self.d("update_unconfirmed_bytes(%d); count: %d" % (num_bytes, self.bytes_unconfirmed))


    # Return an estimate as to how long the specified number of transactions
    # will take.
    @staticmethod
    def get_time_estimate(num_blocks, chain):
        mins = num_blocks
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


    # Initializes the txrecords list of lists.  See comment below.
    def init_txrecords_and_ending_noop_array(self):

        # A list that holds lists of TxRecords.  Entries in the top list
        # correspond to generations of records (there are more than one when
        # num_transactions > 1).  Inner lists track the progression of
        # TxRecords.  Once a transaction surpasses the
        # CONFIRMATION_THRESHOLD_* value, it is removed, as we are certain
        # it will not be reverted.
        self.txrecords = []

        # Tracks whether the termination record was sent in this generation.
        self.ending_noop_sent = []
        self.num_ending_noops_sent = 0
        for i in range(0, self.num_transactions):
            self.txrecords.append([])
            self.ending_noop_sent.append(False)


    # Makes a P2SH address given script bytes.
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


    # Returns a string representation of this Publication object.
    def __str__(self):
        s = "\n\n"
        for generation in range(0, len(self.txrecords)):
            s += "\tGen %d:\n" % generation
            for txrecord in self.txrecords[generation]:
                s += "\t\t" + str(txrecord) + "\n"
        return "Publication:\n\tFile path: %s\n\tFilename: %s\n\tFile size: %d\n\tTemporal key: %s\n\tBytes unconfirmed: %d%s" % (self.filepath, self.filename, self.filesize, binascii.hexlify(self.temporal_key).decode('ascii'), self.bytes_unconfirmed, s)


    # Argument must be of size 'single_output_size'
    def make_redeem_script(self, byte_block):
        byte_block_len = len(byte_block)

        # If the block is not aligned to 32 bytes, then we need to pad it with
        # zeros.
        mod = byte_block_len % 32
        if mod != 0:
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


    # Begins the publication process.
    def begin(self):
        self.v('Beginning to publish %s using %d outputs per %d transaction%s / %d bytes per transaction.' % (self.filepath, self.num_outputs, self.num_transactions, 's' if (self.num_transactions > 1) else '', self.num_bytes_per_tx))

        # The number of blocks is calculated based on the file size, number of
        # bytes per transaction, and number of transactions we send per block.
        # Two is added to account for the termination message and the sending
        # of change upon completion.
        num_blocks = math.ceil(self.filesize / (self.num_transactions * self.num_bytes_per_tx)) + 2

        # If multiple transactions are selected, the beginning and ending NOOPs
        # must be accounted for as well.
        if self.num_transactions > 1:
            num_blocks += 2


        self.v('%s is %d bytes long.  Publication will take %d blocks, which, under optimal conditions, will take %s.' % (self.filepath, self.filesize, num_blocks, Publication.get_time_estimate(num_blocks, self.blockchain)))

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

        txrecord = TxRecord([redeem_script], [p2sh_address], bytes_to_read)
        self.update_unconfirmed_bytes(bytes_to_read)

        # Since this is the first record, add it to the beginning of all
        # generations.
        for i in range(0, self.num_transactions):
            self.txrecords[i].append(txrecord)

        # Estimate the cost to publish this file, then tell the user where &
        # how much to send.
        cost, unused0, unused1, unused2, unused3, num_block_generations, unused5, unused6 = Utils.get_estimate(self.rpc_client, self.filepath, self.blockchain, self.num_outputs, self.num_transactions, self.txfee)
        print("To begin publication, send %.8f %s to %s" % (cost + 0.00000001, self.get_currency_str(), p2sh_address))

        self.write_unit_test_info(p2sh_address, cost+0.00000001, self.block_listener.port)

        cli = 'bitcoin-cli'
        if self.blockchain == Publication.BLOCKCHAIN_DOGE:
            cli = 'dogecoin-cli'

        self.d("%s sendtoaddress %s %.8f; i=0; while [ $i -lt %d ]; do %s generate 1 $PUBKEY; sleep 1.2; let \"i++\"; done" % (cli, p2sh_address, cost, num_block_generations, cli))

        # Wait for a transaction to get at least 1 confirmation which paid us
        # to begin.
        self.wait_for_funds(txrecord, p2sh_address)

        print("Received funds.  Beginning publication...")
        self.received_funds = True

        # Check that the amount sent by the user meets the minimum.
        sent_amount = 0.0
        for value in txrecord.get_values():
            sent_amount += float(value)
        if sent_amount < cost:
            print("Warning: only %.8f was sent instead of the minimum (%.8f)!" % (sent_amount, cost))
        txrecord.set_total_amount(sent_amount)


        # If we are trying to publish a deadman switch key, set
        # end_of_file_reached to True in order to skip the termination message,
        # which isn't necessary.
        if self.deadman_switch_key_publish_mode:
            self.end_of_file_reached = True
            self.termination_record_sent = True

        self.resume()


    # If self.txrecords is be properly configured, this resumes publication.
    def resume(self):

        continue_flag = True
        first_block = True
        sending_termination_record = False
        sending_change = False
        while continue_flag:

            #
            # This is a complex structure used to track what records need to be
            # transmitted, and what their predecessors are.  There are 4 cases
            # for it:
            #
            # 1. One input record goes to multiple output records.  This
            # happens at the start of a publication when multiple transactions
            # used.  NOOPs are used to split the one input into multiple
            # outputs.  The structure would look like this:
            #
            # [([previous_txrecord], [next_txrecord1, next_txrecord2, ...])]
            #
            #
            # 2. One input record goes to one output record.  This happens
            # when one transaction per block is used.  The structure would
            # look like this:
            #
            # [([previous_txrecord], [next_txrecord])]
            #
            #
            # 3. One input record goes to one output record, and there are
            # multiple pairs.  This happens when multiple transactions per
            # block is used.  The structure would look like this:
            #
            # [([previous_txrecord1], [next_txrecord1]),
            #  ([previous_txrecord2], [next_txrecord2]), ...]
            #
            #
            # 4. Multiple input records go to a single output.  This happens
            # at the end of a multiple-transaction publication to join the
            # generations back into one (using NOOPs).  The structure would
            # look like this:
            #
            # [([previous_txrecord1, previous_txrecord2, ...], next_txrecord)]
            #
            #
            txrecords_to_transmit = []

            if first_block and (self.num_transactions > 1):
                self.d("Creating initial NOOP messages...")
                previous_txrecord = self.txrecords[0][-1]

                next_txrecords = []
                for generation in range(0, self.num_transactions):
                    next_txrecord = self.create_noop_record()
                    self.txrecords[generation].append(next_txrecord)
                    next_txrecords.append(next_txrecord)

                txrecords_to_transmit = [([previous_txrecord], next_txrecords)]

            elif (self.num_transactions == 1) and (self.end_of_file_reached is False):
                self.d("Creating next block for single-transaction publication...")
                previous_txrecord = self.txrecords[0][-1]

                next_txrecord = self.create_next_txrecord()
                self.add_txrecord(previous_txrecord, next_txrecord)
                txrecords_to_transmit = [([previous_txrecord], [next_txrecord])]

            elif (self.num_transactions > 1) and (self.num_ending_noops_sent != self.num_transactions):
                self.d("Creating next blocks for multi-transaction publication...")

                for generation in range(0, self.num_transactions):
                    previous_txrecord = self.txrecords[generation][-1]

                    if self.end_of_file_reached:
                        if self.ending_noop_sent[generation]:
                            continue

                        self.d("Creating ending NOOP for generation %d" % generation)
                        next_txrecord = self.create_noop_record()
                        self.ending_noop_sent[generation] = True
                        self.num_ending_noops_sent += 1
                    else:
                        next_txrecord = self.create_next_txrecord()

                    self.add_txrecord(previous_txrecord, next_txrecord)
                    txrecords_to_transmit.append(([previous_txrecord], [next_txrecord]))

            elif self.termination_record_sent is False:
                self.d("Sending termination record...")

                termination_txrecord = self.create_termination_record()
                termination_txrecord.set_last_record()

                last_txrecords = []
                for generation in range(0, self.num_transactions):
                    # Get all the previous records.
                    last_txrecords.append(self.txrecords[generation][-1])

                    # Append the termination record to the end of all generations.
                    self.txrecords[generation].append(termination_txrecord)

                txrecords_to_transmit = [(last_txrecords, [termination_txrecord])]
                sending_termination_record = True
            else:
                termination_txrecord = self.txrecords[0][-1]

                print("Sending about %.8f in change to %s..." % (termination_txrecord.get_total_amount(), self.change_address))
                sending_change = True
                txrecords_to_transmit = [([termination_txrecord], [TxRecord([], [self.change_address], 0)])]

            # Now transmit/re-transmit all the txrecords.
            self.transmit_txrecords(txrecords_to_transmit)

            first_block = False

            if sending_termination_record:
                self.termination_record_sent = True

                # Add termination record to the end of all generations.
                for generation in range(0, self.num_transactions):
                    self.txrecords[generation].append(termination_txrecord)

            if sending_change:
                self.change_sent = True
                continue_flag = False


        print("\nPublication complete!  Waiting for the transactions to surpass the confirmation threshold.  This phase is optional.")

        # Keep waiting until all TxRecords have surpassed the confirmation
        # threshold.
        while not self.complete:
            self.wait_for_new_block([], True)

            i = 0
            self.d("\nTxRecords:")
            for generation in self.txrecords:
                for txrecord in generation:
                    i += 1
                    self.d("\t%s" % txrecord)
            print("%d transactions awaiting full confirmation..." % i)

        print("All transactions fully confirmed.")


    # Transmits/re-transmits TxRecords.
    def transmit_txrecords(self, txrecords_to_transmit):

            # Now transmit/re-transmit all the txrecords.
            while len(txrecords_to_transmit) > 0:

                txrecords_to_watch = []
                initial_nop_split = False
                for transaction in txrecords_to_transmit:
                    previous_txrecords = transaction[0]
                    next_txrecords = transaction[1]

                    next_txrecord = None
                    if len(next_txrecords) == 1:
                        next_txrecord = next_txrecords[0]

                    # Handle case #1 (see huge comment on
                    # txrecords_to_transmit, above).
                    else:
                        initial_nop_split = True

                        redeem_scripts = []
                        p2sh_addresses = []
                        for txr in next_txrecords:
                            redeem_scripts.extend(txr.redeem_scripts)
                            p2sh_addresses.extend(txr.p2sh_addresses)

                        next_txrecord = TxRecord(redeem_scripts, p2sh_addresses, 0)

                    # Send this transaction on its way!
                    self.send_transaction(previous_txrecords, next_txrecord)
                    txrecords_to_watch.append(next_txrecord)

                self.d("Waiting for next block...")
                self.wait_for_new_block(txrecords_to_watch)

                # Handle case #1 (see huge comment on txrecords_to_transmit,
                # above).
                if initial_nop_split and (txrecords_to_watch[0].get_confirmations() > 0):
                    self.d("Handling NOOP split...")
                    bogus_txrecord = txrecords_to_watch[0]
                    for generation in range(0, self.num_transactions):

                        temp_txrecord = self.txrecords[generation][-1]
                        temp_txrecord.set_txid(bogus_txrecord.get_txid())
                        temp_txrecord.set_total_amount(bogus_txrecord.get_total_amount() / self.num_transactions)
                        temp_txrecord.set_confirmations(bogus_txrecord.get_confirmations())

                        temp_txrecord.add_output_script(bogus_txrecord.output_scripts.pop(0))
                        temp_txrecord.add_vout_num(bogus_txrecord.vout_nums.pop(0))
                        temp_txrecord.add_value(bogus_txrecord.values.pop(0))

                    # The number of confirmations is 1 or more, so no need to
                    # retransmit.
                    txrecords_to_transmit = []

                else:

                    # Go through all the ones we were watching.
                    for watched_txrecord in txrecords_to_watch:
                        # If this one has 1 or more confirmations...
                        if watched_txrecord.get_confirmations() > 0:
                            # ... remove it from the to-transmit list.
                            for transaction in txrecords_to_transmit:
                                if transaction[1][0] == watched_txrecord:
                                    txrecords_to_transmit.remove(transaction)
                        else:
                            self.d("TXID not confirmed in last block: %s" % watched_txrecord.get_txid())

                num_retransmit = len(txrecords_to_transmit)
                if num_retransmit > 0:
                    self.d("Re-transmitting %d unconfirmed records..." % num_retransmit)


    # Creates and returns a TxRecord with a termination message.
    def create_termination_record(self):
        key = self.temporal_key
        iv = self.temporal_iv
        extra = self.temporal_extra

        # If the deadman switch is enabled, overwrite the key information.
        if self.deadman_switch_path is not None:
            key = b'\xff' * 32
            iv = b'\xff' * 32
            extra = b'\xff' * 32

        # 8 bytes to denote the end of the file
        # 8 bytes for the nonce
        # 32 bytes for the nonce hash
        # 4 reserved bytes
        # 32 bytes for the temporal encryption key
        # 32 bytes for the temporal IV (currently not used)
        # 32 bytes for extra encryption data (currently not used)
        nonce = os.urandom(Publication.NONCE_LEN)
        nonce_hash = hashlib.sha256(Publication.HEADER_TERMINATE + nonce + Publication.NONCE_SALT).digest()
        header_termination_bytes = Publication.HEADER_TERMINATE + \
            nonce + \
            nonce_hash + \
            b'\x00\x00\x00\x00' + \
            key + \
            iv + \
            extra

        self.d("\nTermination bytes: %s" % binascii.hexlify(header_termination_bytes).decode('ascii'))

        redeem_script, p2sh_address = self.make_redeem_script(header_termination_bytes)
        return TxRecord([redeem_script], [p2sh_address], 0)


    # Creates and returns a TxRecord with a NOOP message.
    def create_noop_record(self):
        nonce = os.urandom(Publication.NONCE_LEN)
        nonce_hash = hashlib.sha256(Publication.HEADER_NOOP + nonce + Publication.NONCE_SALT).digest()
        header_noop_bytes = Publication.HEADER_NOOP + nonce + nonce_hash

        redeem_script, p2sh_address = self.make_redeem_script(header_noop_bytes)
        return TxRecord([redeem_script], [p2sh_address], 0)


    # Creates the next TxRecord, based on the number of bytes previously read
    # from the file.
    def create_next_txrecord(self):
        redeem_scripts = []
        p2sh_addresses = []

        file_pos = self.get_file_position()

        # Pack the file position integer into bytes to insert into the message.
        file_offset_packed = struct.pack('!I', file_pos)

        total_bytes_read = 0
        for i in range(0, self.num_outputs):
            next_block = b''

            # If we are doing a plaintext publication, prepend a nonce to
            # each output.
            if self.nocrypto:
              next_block = os.urandom(Publication.NONCE_LEN)

            # Include the offset if this is the first output in a transaction.
            if i == 0:
              next_block += file_offset_packed

            num_bytes_to_read = Publication.SINGLE_OUTPUT_SIZE - len(next_block)
            if file_pos + total_bytes_read + num_bytes_to_read >= len(self.file_bytes):
                num_bytes_to_read = len(self.file_bytes) - file_pos
                self.end_of_file_reached = True

            next_block += self.file_bytes[file_pos + total_bytes_read:file_pos + total_bytes_read + num_bytes_to_read]

            redeem_script, p2sh_address = self.make_redeem_script(next_block)
            redeem_scripts.append(redeem_script)
            p2sh_addresses.append(p2sh_address)

            total_bytes_read += num_bytes_to_read

            if self.end_of_file_reached:
              break

        self.update_unconfirmed_bytes(total_bytes_read)
        return TxRecord(redeem_scripts, p2sh_addresses, total_bytes_read)


    # Transmits a transaction.
    def send_transaction(self, txrecords, next_txrecord, recurse_level=0):

        # Using a bogus amount, get the length of this signed transaction
        signed_raw_tx_hex = self.create_and_sign_tx(txrecords, next_txrecord.p2sh_addresses, 0.00000001)
        tx_len = len(signed_raw_tx_hex) / 2
        self.d("Length of signed message: %d" % tx_len)

        total_amount = 0
        for txrecord in txrecords:
            total_amount += txrecord.get_total_amount()

        next_total_amount, per_output_amount = Publication.get_tx_output_amount(self.d, self.blockchain, total_amount, self.txfee, tx_len, min(self.num_outputs, len(next_txrecord.p2sh_addresses)), recurse_level)
        next_txrecord.set_total_amount(next_total_amount)

        # If we reached the end of the file, we send the final amount to one
        # single P2SH address
        if self.change_sent:
            self.d("Sending %.8f to change address." % per_output_amount)
        else:
            self.d("Sending %.8f per output." % per_output_amount)

        signed_raw_tx_hex = self.create_and_sign_tx(txrecords, next_txrecord.p2sh_addresses, per_output_amount)
        self.d("Signed raw_tx: %s" % signed_raw_tx_hex)

        nbytes = 0
        for txr in txrecords:
            nbytes += txr.num_bytes

        if nbytes > 0:
            num_signed_raw_tx_bytes = len(signed_raw_tx_hex) / 2
            efficiency = nbytes / num_signed_raw_tx_bytes
            overhead = (num_signed_raw_tx_bytes - nbytes) / nbytes
            self.d("Number of payload bytes: %d; number of bytes in signed raw tx: %d; efficiency: %.8f; overhead multiplier: %.8f" % (nbytes, num_signed_raw_tx_bytes, efficiency, (overhead + 1.0)))

        next_txid = ''
        try:
            next_txid = self.rpc_client.sendrawtransaction(signed_raw_tx_hex)
        except urllib.error.HTTPError as e:
            emesg = e.read().decode('ascii')

            # If the server complained that this transaction is already in the
            # blockchain, continue on.  Otherwise, re-throw the exception.
            if (e.code == 500) and (emesg.find('transaction already in block chain') != -1):
                # Get this transaction's TXID if sendrawtransaction had
                # succeeded.
                next_txid = self.rpc_client.decoderawtransaction(signed_raw_tx_hex)['txid']
                self.d("Failed to send raw transaction: %s: %s\n\n[%s]" % (next_txid, e.read().decode('ascii'), signed_raw_tx_hex))

            # Very rarely, Dogecoin transactions fail to send due to
            # 'insufficient priority' even though enough fees are given.  This
            # has been observed to occur at inconsistent points during unit
            # testing, suggesting that there is some sort of temporal hiccup in
            # the Dogecoin codebase.
            #
            # This code is an experimental attempt at working around the
            # problem.  When encountered, we will recurse and bump up the fee
            # by 1 or 2 DOGE to see if the transaction is accepted.
            elif (emesg.find('insufficient priority') != -1) and (self.blockchain == Publication.BLOCKCHAIN_DOGE):

                # Only recurse two levels deep.
                if recurse_level > 2:
                    self.d('Failed to send transaction even after 2 recurse levels. raw tx: [%s]' % signed_raw_tx_hex)
                    exit(-1)

                # Recurse and try again.  get_tx_output_amount() tracks the
                # recurse level, and will bump up the fee by 1 or 2 DOGE.
                return self.send_transaction(txrecords, next_txrecord, recurse_level + 1)

            else:
                self.d("Exception in sendrawtransaction: error code %d: %s; raw tx: [%s]" % (e.code, emesg, signed_raw_tx_hex))

        if len(next_txid) == 64:
            self.d("Sent!: %s" % next_txid)
            next_txrecord.set_txid(next_txid)

            # If we are in deadman switch mode, and did not yet write out the
            # key, do that now.
            self.store_deadman_switch_key(next_txid)
        else:
            print('Failed to send transaction: [%s]' % signed_raw_tx_hex)
            exit(-1)


    # Creates a raw transaction and signs it.
    def create_and_sign_tx(self, txrecords, p2sh_addresses, amount):
        inputs = []
        stuffs = []

        # This must be a string instead of dictionary, because order is
        # extremely important (a dictionary often changes the order
        # automatically).  If this is out of order, then file data is
        # transmitted incorrectly.
        outputs_str = '{'
        for p2sh_address in p2sh_addresses:
            outputs_str += "\"%s\": %.8f," % (p2sh_address, amount)
        outputs_str = outputs_str[:-1] + '}'


        for txrecord in txrecords:
            txid = txrecord.txid

            for vout_num in txrecord.get_vout_nums():
                input = {}
                input['txid'] = txid
                input['vout'] = vout_num
                inputs.append(input)


            output_scripts = txrecord.get_output_scripts()
            vout_nums = txrecord.get_vout_nums()

            if len(vout_nums) != len(txrecord.redeem_scripts):
                print("Len mismatch: %d, %d" % (len(vout_nums), len(txrecord.redeem_scripts)))
                print("vout_nums: %s" % ', '.join(str(x) for x in vout_nums))


            for i in range(0, len(txrecord.redeem_scripts)):
                stuff = {}
                stuff['txid'] = txid
                stuff['vout'] = vout_nums[i]
                stuff['scriptPubKey'] = output_scripts[i]
                stuff['redeemScript'] = binascii.hexlify(txrecord.redeem_scripts[i]).decode('ascii')
                stuffs.append(stuff)

        unsigned_raw_tx = None
        try:
            unsigned_raw_tx = self.rpc_client.createrawtransaction(json.dumps(inputs), outputs_str)
        except urllib.error.HTTPError as e:
            print(e.read().decode('ascii'))
            raise(e)

        signed_raw_tx = self.rpc_client.signrawtransaction(unsigned_raw_tx, stuffs, self.privkey)
        return signed_raw_tx['hex']


    # Called only when restoring a Publication.
    def set_unittest_publication_address(self, unittest_publication_address):
        self.unittest_publication_address = unittest_publication_address
        self.write_unit_test_info('X', 0.0, self.block_listener.port)


    # Writes the publication address, initial required funds, and the
    # BlockListener's port to a file.  Used by the unit testing framework to
    # determine how to kick off a publication automatically.
    def write_unit_test_info(self, p2sh_address, cost, block_listener_port):
        if self.unittest_publication_address is not None:
            with open(self.unittest_publication_address, 'w') as f:
                fcntl.lockf(f, fcntl.LOCK_EX)
                f.write("%s %.8f %d" % (p2sh_address, cost, block_listener_port))


    # Wait for at least one block to be generated, then update the
    # confirmations for the txrecords argument.
    def wait_for_new_block(self, txrecords, purge = False):

        # Wait for new blocks to come in.  We don't care about what they
        # are, since we get the raw transactions using TXIDs below.
        self.block_listener.wait_for_blocks()

        # Update the confirmation count for all TxRecords we are currently
        # maintaining.
        self.update_confirmations(purge)
        for txrecord in txrecords:
            txid = txrecord.get_txid()

            # If we are looking for a specific TXID...
            if txid is not None:
                # Try to get the JSON of the raw transaction.
                rawtransaction = self.rpc_client.getrawtransaction(txid, 1)

                # Check if it has a "confirmations" field.  If not, this
                # TXID is still unconfirmed.
                if 'confirmations' in rawtransaction:
                    confirmations = int(rawtransaction['confirmations'])
                    if confirmations > 0:
                        txrecord.set_confirmations(confirmations)
                        if len(txrecord.get_output_scripts()) == 0 and len(txrecord.get_vout_nums()) == 0 and len(txrecord.get_values()) == 0:
                            vouts = rawtransaction['vout']
                            for vout in vouts:
                                txrecord.add_output_script(vout['scriptPubKey']['hex'])
                                txrecord.add_vout_num(int(vout['n']))
                                txrecord.add_value(vout['value'])
                else:
                    self.d("No confirmation for %s" % txid)


    # Waits for initial publication funds to be sent to the publication
    # address.
    def wait_for_funds(self, txrecord, recipient_address):

        while True:

            block_hashes = self.block_listener.wait_for_blocks()
            for block_hash in block_hashes:

                # Get the transactions in the block pointed to by this block
                # hash, then loop through them and parse them all.
                block_txs = self.rpc_client.getblock(block_hash)['tx']
                for tx in block_txs:
                    try:
                        rawtransaction = self.rpc_client.getrawtransaction(tx, 1)
                    except Exception as e:
                        print('Error while trying to retrieve TXID %s: %s' % (tx, str(e)))
                        continue

                    vouts = rawtransaction['vout']
                    for vout in vouts:
                        if (vout['scriptPubKey']['type'] == 'scripthash') and (recipient_address in vout['scriptPubKey']['addresses']):
                            txrecord.set_txid(tx)
                            txrecord.set_confirmations(int(rawtransaction['confirmations']))
                            txrecord.add_output_script(vout['scriptPubKey']['hex'])
                            txrecord.add_vout_num(int(vout['n']))
                            txrecord.add_value(vout['value'])
                            self.d('Found sent funds (%s) in TXID %s' % (vout['value'], tx))
                            return

                self.d('Did not find funds in block %s' % block_hash)


    # Updates the confirmation count for all tracked transactions.  If purge is
    # True, a full purge of records is done, if the confirmations surpass the
    # threshold.  Otherwise, the last record for each generation is preserved,
    # regardless of its confirmation number.
    def update_confirmations(self, purge = False, update_vout = False):
        # The list of TXIDs to re-transmit due to network forks turning
        # previously-confirmed transactions to an unconfirmed state.
        retransmit = []

        # Update all the confirmation counts for all TxRecords in the list.
        for i in range(0, self.num_transactions):
            for txrecord in self.txrecords[i]:
                txid = txrecord.get_txid()
                previous_confirmations = txrecord.get_confirmations()
                if txid is not None:
                    try:
                        rawtransaction = self.rpc_client.getrawtransaction(txid, 1)
                    except Exception as e:
                        print(str(e))
                        print("getrawtransaction exception: %s" % txid)
                        exit(-1)

                    if 'confirmations' in rawtransaction:
                        txrecord.set_confirmations(int(rawtransaction['confirmations']))
                    else: # Explicitly set it to 0, in case of a network fork.
                        txrecord.set_confirmations(0)

                    if update_vout and 'vout' in rawtransaction and len(txrecord.get_output_scripts()) == 0 and len(txrecord.get_vout_nums()) == 0 and len(txrecord.get_values()) == 0:
                        vouts = rawtransaction['vout']
                        for vout in vouts:
                            txrecord.add_output_script(vout['scriptPubKey']['hex'])
                            txrecord.add_vout_num(int(vout['n']))
                            txrecord.add_value(vout['value'])

                # If any TXIDs in our lists have zero confirmations (except for
                # the ones at the end), then a network fork occurred and
                # converted them into unconfirmed transactions.  We will
                # re-transmit them to speed up propagation across the memory
                # pools.
                #
                # This re-transmission may not be strictly necessary (as the
                # wallet should re-transmit them), but in a test environment,
                # foreign nodes were not observed to receive the unconfirmed
                # transactions from the original sender even after a few hours
                # (though they remained in the sender's mempool).
                # Re-transmitting them here is theorized to speed up
                # propagation, in hopes of speeding up resumption of
                # publication.  Either way, it can't hurt, sooo...
                if (txrecord.get_confirmations() == 0) and (txrecord.get_txid() is not None) and (self.txrecords[i].index(txrecord) != (len(self.txrecords[i]) - 1)):
                    self.d('Network fork detected, which caused TXID %s to become unconfirmed%s.  Re-transmitting it now...' % (txrecord.get_txid(), ' (from %d confirmations)' % previous_confirmations if previous_confirmations > 0 else ''))

                    try:
                        self.rpc_client.sendrawtransaction(self.rpc_client.getrawtransaction(txid, 0))
                    except urllib.error.HTTPError as e:
                        self.d('An exception was caught while re-transmitting TXID %s (this can probably be ignored): %d: %s' % (txid, e.code, e.read().decode('ascii')))


        # Go through the list again now that all confirmation counts are
        # updated.  If the current TxRecord is passed the threshold as well as
        # the next one, remove the current TxRecord.  The next record matters
        # because to re-transmit a transaction, information from the previous
        # TxRecord (its redeemscripts) are needed.
        confirmation_threshold = self.get_confirmation_threshold()
        for i in range(0, self.num_transactions):
            generation = self.txrecords[i]
            j = 0
            while j < len(generation) - 1:
                txrecord_cur = generation[j]
                txrecord_next = generation[j + 1]

                if (txrecord_cur.get_confirmations() > confirmation_threshold) and (txrecord_next.get_confirmations() > confirmation_threshold) and (purge or len(self.txrecords[i]) > 2):
                    self.d("TXID %s has surpassed the confirmation threshold (%d)." % (txid, confirmation_threshold))
                    generation.remove(txrecord_cur)
                else:
                    j += 1

            if purge and (len(generation) == 1):
                txrecord = generation[0]
                if txrecord.is_last_record() and (txrecord.get_confirmations() > confirmation_threshold):
                    self.d("Last TXID (%s) surpassed the confirmation threshold." % txrecord.get_txid())
                    self.txrecords[i] = []

        # Update the is_complete flag.  This will be True only if all
        # generations are empty lists.
        is_complete = True
        for i in range(0, self.num_transactions):
            is_complete = is_complete and (self.txrecords[i] == [])

        self.complete = is_complete


    # Given a CONTENT_TYPE_ constant, return its string representation.
    @staticmethod
    def get_content_type_str(content_type):
        if content_type not in Publication.CONTENT_TYPE_MAP:
            return 'unknown'

        return Publication.CONTENT_TYPE_MAP[content_type]


    # Given a content type string, return its CONTENT_TYPE_* constant, or
    # False if invalid.
    @staticmethod
    def get_content_type_const(content_type_str):
        ctypes = {v: k for k, v in Publication.CONTENT_TYPE_MAP.items()}
        if content_type_str not in ctypes:
            return False

        return ctypes[content_type_str]


    # Given a COMPRESSION_TYPE_ constant, return its string representation.
    @staticmethod
    def get_compression_type_str(compression_type):
        if compression_type not in Publication.COMPRESSION_TYPE_MAP_STR:
            return 'unknown'

        return Publication.COMPRESSION_TYPE_MAP_STR[compression_type]


    # Given a compression type string, return its COMPRESSTION_TYPE_* constant,
    # or False if invalid.
    @staticmethod
    def get_compression_type_const(compression_type_str):
        ctypes = {v: k for k, v in Publication.COMPRESSION_TYPE_MAP_STR.items()}
        if compression_type_str not in ctypes:
            return False

        return ctypes[compression_type_str]


    # Given an ENCRYPTION_TYPE_ constant, return its string representation.
    @staticmethod
    def get_encryption_str(encryption_type):
        if encryption_type not in Publication.ENCRYPTION_TYPE_MAP:
            return 'unknown'

        return Publication.ENCRYPTION_TYPE_MAP[encryption_type]
