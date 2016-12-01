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


# The method in this class parses blocks in the blockchain and extracts data
# from them.

from PartialFile import *
from Publication import *

class BlockParser:

    @staticmethod
    def init(d, log, rpc_client, output_dir, partial_dir, content_filter = None):
        BlockParser.d = d
        BlockParser.log = log
        BlockParser.rpc_client = rpc_client
        BlockParser.output_dir = output_dir
        BlockParser.partial_dir = partial_dir
        BlockParser.content_filter = content_filter


    # Decrypts a deadman switch file, given a key.  Stores the decrypted file
    # in the output directory.  Returns True on success, or False if no matching
    # deadman switch file was found (or an error occurred).
    @staticmethod
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
                partial_file.debug_func = BlockParser.d
                return partial_file.finalize(key, -1)

        BlockParser.log('Failed to find a matching deadman switch file with TXID: %s' % txid_hex)
        return False


    # Processes a block by inspecting its transactions and parsing any included
    # data.
    @staticmethod
    def parse_block(current_block_num, current_block_hash, current_block = None):

        # If the parsed block wasn't provided, parse it now.
        if current_block is None:
            current_block = BlockParser.rpc_client.getblock(current_block_hash)

        # Load all the partial files.
        partial_files = PartialFile.load_state_files(BlockParser.d, BlockParser.partial_dir)
        BlockParser.d("Loaded %d partial files" % len(partial_files))

        # Get all the interesting TXIDs so we know what to look for in this
        # block.
        interesting_txids = {}
        for partial_file in partial_files:
            previous_txids = partial_file.get_previous_txids()
            for previous_txid in previous_txids:
                BlockParser.d("Interesting TXID: %s" % previous_txid)
                interesting_txids[previous_txid] = partial_file

        # Get the transactions in this block.  Loop through each one and parse
        # it.
        txids = current_block['tx']
        for txid in txids:
            bytes_to_write = b''
            file_offset = -1
            partial_file = None

            raw_tx = BlockParser.rpc_client.getrawtransaction(txid, 1)

            vins = raw_tx['vin']
            for vin in vins:
                if 'txid' in vin:
                    vin_txid = vin['txid']
                    scriptSig_hex = vin['scriptSig']['hex']
                    scriptSig_bin = binascii.unhexlify(scriptSig_hex)

                    # Look for the header denoting the start of a new file.
                    header_pos = scriptSig_bin.find(Publication.HEADER_BEGIN)
                    if header_pos >= 2:
                        BlockParser.d("Found potential publication header in %s" % txid)

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
                            BlockParser.log("Nonce hash does not match!")
                            BlockParser.d("Computed hash: %s; extracted: %s" % (binascii.hexlify(computed_nonce_hash), binascii.hexlify(nonce_hash)))
                            continue
                        else:
                            BlockParser.d("Nonce hashes match.")

                        # Skip over the two reserved bytes.
                        reserved = data[ptr:ptr + 2]
                        ptr += 2

                        # general flags, encryption, content, compression,
                        # file_size
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

                        # Strip out any relative paths embedded into the
                        # filename.  The basename() call is enough, but we'll
                        # throw in some manual replacement just to be extra
                        # sure.
                        sanitized_filename = os.path.basename(filename).replace('\\', '').replace('/', '')

                        partial_file = PartialFile(BlockParser.d, txid, BlockParser.output_dir, BlockParser.partial_dir, sanitized_filename, description, file_size, general_flags, encryption_type, content_type, compression_type, file_hash, current_block_num)

                        # If there is a content filter in place, check to see
                        # if this PartialFile matches.  If not, skip it.
                        if (BlockParser.content_filter is not None) and (BlockParser.content_filter.matches(partial_file) is False):
                            partial_file = None
                            continue

                        # Is this a deadman switch key?  If so, ensure that the
                        # payload has at least 128 bytes (it should be exactly
                        # 128, but there may be padding at this point still).
                        if partial_file.is_deadman_switch_key() and (len(data) >= 128):
                            BlockParser.log('DISCOVERED DEADMAN SWITCH KEY!: ' + binascii.hexlify(data).decode('ascii'))
                            if BlockParser.decrypt_deadman_switch_file(partial_files, data):
                                BlockParser.log('Successfully decrypted deadman switch file!')
                            else:
                                BlockParser.log('Failed to decrypt deadman switch file.')
                        else:
                            BlockParser.log("Discovered publication: %s" % partial_file)
                            partial_file.write_data(data, 0, current_block_num)
                            partial_file.save_state()
                            partial_file = None

                    # Header bytes not found.  Let's check this transaction
                    # references any TXIDs that we've previously processed.  If 
                    # present, this would mean they have continuation data we
                    # need to extract.
                    else:
                        if vin_txid in interesting_txids:
                            data = Utils.get_data_from_scriptsig(BlockParser.d, scriptSig_bin)
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
                                    BlockParser.d('NOOP nonce does not match.')


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

                                if partial_file.finalize(temporal_key, current_block_num):
                                    BlockParser.log("Successfully retrieved file: %s" % partial_file)
                                else:
                                    BlockParser.log("Failed to retrieve file: %s" % partial_file)

                                if partial_file.is_deadman_switch_file():
                                    BlockParser.log("Deadman switch file retrieved.")


                                partial_file = None

                            elif noop_data: # Don't do anything special.
                                partial_file.add_previous_txid(txid)
                                partial_file.save_state()
                                BlockParser.d('Found NOOP; adding: %s' % txid)
                            else:  # This is continuation data...
                                partial_file.add_previous_txid(txid)

                                if (file_offset == -1) and (len(data) > 4):
                                    file_offset = struct.unpack('!I', data[0:4])[0]
                                    data = data[4:]

                                bytes_to_write += data

                        else:
                            BlockParser.d('vin_txid not in interesting IDs: %s' % vin_txid)

            # Once all inputs have been processed in this TXID...
            if file_offset >= 0 and bytes_to_write != b'' and \
               partial_file is not None:
                BlockParser.d("Writing %d bytes to offset %d: %s" % (len(bytes_to_write), file_offset, binascii.hexlify(bytes_to_write)))
                partial_file.write_data(bytes_to_write, file_offset, current_block_num)
                partial_file.save_state()
