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


# This static class holds various helper functions.

import base64, binascii, math, os, subprocess, struct, sys, tempfile

class Utils:
    BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    # Converts a byte array to a Base58 string.
    @staticmethod
    def base58_encode(the_bytes):
        hex_bytes = binascii.hexlify(the_bytes).decode('ascii')
        if len(hex_bytes) % 2:
            hex_bytes = '0x0' + hex_bytes
        else:
            hex_bytes = '0x' + hex_bytes

        bigendian_num = int(hex_bytes, 16)

        ret = []
        while bigendian_num > 0:
            bigendian_num, remainder = divmod(bigendian_num, 58)
            ret.append(Utils.BASE58_CHARS[remainder])

        padding = []
        for i in the_bytes:
            if i == b'\x00':
                padding.append('1')
            else:
                break

        return ''.join(padding + ret[::-1])


    # Compresses a file using the method specified by a COMPRESSION_TYPE_
    # constant.
    @staticmethod
    def compress_file(filepath, compression):
        from Publication import Publication

        ret_bytes = b''

        # Some programs (like the zip program) refuse to write to existing
        # files if they're not valid archives already.  So we'll have to make
        # them write to stdout instead.
        try:
            if compression == Publication.COMPRESSION_TYPE_ZIP:
                ret_bytes, stderr = Utils.exec(['zip', '-9', '-', filepath])
            elif compression == Publication.COMPRESSION_TYPE_GZIP:
                ret_bytes, stderr = Utils.exec(['gzip', '-9', '-n', '--stdout', filepath])
            elif compression == Publication.COMPRESSION_TYPE_BZIP2:
                ret_bytes, stderr = Utils.exec(['bzip2', '-q', '-9', '--stdout', filepath])
            elif compression == Publication.COMPRESSION_TYPE_XZ:
                ret_bytes, stderr = Utils.exec(['xz', '-q', '-9', '-e', '--stdout', filepath])
            elif compression == Publication.COMPRESSION_TYPE_LZMA:
                ret_bytes, stderr = Utils.exec(['lzma', '-q', '-9', '-e', '--stdout', filepath])
            #
            # 7zip compression no happy.  :(
            #
            #elif compression == Publication.COMPRESSION_TYPE_7ZIP:
            #    fd, temp_compressed = tempfile.mkstemp(suffix='.7z')
            #    os.close(fd)
            #    stdout, stderr = Utils.exec(['7z', 'a', '-t7z', '-m0=lzma', '-mx=9', '-mfb=64', '-md=32m', '-ms=on', temp_compressed, filepath])
            #    with open(temp_compressed, 'rb') as f:
            #        ret_bytes += f.read()
            #    os.unlink(temp_compressed)

        except Exception as e:
            print("Error while compressing with %s on %s" % (Publication.COMPRESSION_TYPE_MAP_STR[compression], filepath))

        return ret_bytes


    # Analyzes a filename and attempts to figure out its content type.  Returns
    # a Publication.CONTENT_TYPE_* flag.
    @staticmethod
    def find_content_type(filepath):
        from Publication import Publication

        # Get the file extension.
        dot_pos = filepath.rfind('.')
        if dot_pos == -1:
            return Publication.CONTENT_TYPE_UNDEFINED
        ext = filepath[dot_pos+1:].lower()

        # Is this a document?
        if ext in ['pdf', 'docx', 'doc', 'pptx', 'ppt', 'xlsx', 'xls', 'odt', 'odp', 'ods', 'txt']:
            return Publication.CONTENT_TYPE_DOCUMENT

        # Is this a picture?
        elif ext in ['jpg', 'jpeg', 'png', 'gif', 'ico', 'tif', 'tiff', 'bmp', 'eps', 'ai']:
            return Publication.CONTENT_TYPE_PICTURE

        # Is this sound?
        elif ext in ['mp3', 'wav', 'wma', 'ogg', 'oga', 'aac', 'midi']:
            return Publication.CONTENT_TYPE_SOUND

        # Video?
        elif ext in ['webm', 'mpg', 'mpeg', 'mov', 'mp4', 'mkv', 'avi', 'divx', 'wmv', '3gp', '3g2', 'gifv']:
            return Publication.CONTENT_TYPE_VIDEO

        # Source code?
        elif ext in ['py', 'rb', 'js', 'java', 'c', 'cpp', 'h', 'php', 'cs', 'sh', 'go', 's', 'pl', 'vb', 'vbs', 'ps1', 'bat', 'sol']:
            return Publication.CONTENT_TYPE_SOURCECODE

        # Digital signature?
        elif ext in ['asc', 'sig']:
            return Publication.CONTENT_TYPE_DIGITALSIG

        # Archive?
        elif ext in ['tar', 'zip', 'bz2', 'gz', 'xz', '7z', 'lzma', 'iso', 'gpg', 'pgp']:
            return Publication.CONTENT_TYPE_ARCHIVE


        return Publication.CONTENT_TYPE_UNDEFINED


    # Determines the optimal compression for the specified file path.  Returns
    # a tuple containing the compressed bytes and
    # Publication.COMPRESSION_TYPE_* flag that was selected.
    @staticmethod
    def find_optimal_compression(filepath, v):
        from Publication import Publication

        best_compression_type = Publication.COMPRESSION_TYPE_NONE
        best_compression_bytes = None
        with open(filepath, 'rb') as f:
            best_compression_bytes = f.read()

        best_compression_bytes_len = len(best_compression_bytes)
        best_compression_percentage = 0.0

        original_file_size = best_compression_bytes_len

        v("Finding the optimal compression type for %s (size: %d)..." % (filepath, original_file_size))

        # Get a list of all the COMPRESSION_TYPE_ constants, minus the reserved
        # and none types.
        ctypes = list(Publication.COMPRESSION_TYPE_MAP_STR.keys())
        ctypes.remove(Publication.COMPRESSION_TYPE_RESERVED)
        ctypes.remove(Publication.COMPRESSION_TYPE_NONE)

        # Write the original file to a temporary file.  This obscures the
        # original filename, in case these external programs decide to include
        # it into the output stream.
        fd, temp_original = tempfile.mkstemp()
        with open(filepath, 'rb') as f:
            os.write(fd, f.read())
        os.close(fd)

        # For each compression type, call compress_file() to do that kind of
        # compression, and store the compressed bytes in the dictionary (with
        # type as the key).
        for ctype in ctypes:
            ctype_str = Publication.COMPRESSION_TYPE_MAP_STR[ctype]
            v("Performing %s compression..." % ctype_str)
            ctype_bytes = Utils.compress_file(temp_original, ctype)
            ctype_bytes_len = len(ctype_bytes)

            adj = "smaller" if ctype_bytes_len < original_file_size else "larger"
            percent_change = (abs(ctype_bytes_len - original_file_size) / original_file_size) * 100
            v("\tCompression with %s yields %.1f%% %s file.  Compressed size: %d" % (ctype_str, percent_change, adj, ctype_bytes_len))

            if (ctype_bytes_len < best_compression_bytes_len) and (ctype_bytes_len > 0):
                best_compression_bytes = ctype_bytes
                best_compression_bytes_len = ctype_bytes_len
                best_compression_type = ctype
                best_compression_percentage = percent_change

        v("Optimal compression type is %s: The file is %d bytes (%.1f%%) smaller." % (Publication.COMPRESSION_TYPE_MAP_STR[best_compression_type], original_file_size - best_compression_bytes_len, best_compression_percentage))

        # Delete the temporary file.
        os.unlink(temp_original)
        return best_compression_bytes, best_compression_type


    # Estimates the cost and time to publish the specified file.  'filepath'
    # is the file to estimate, 'chain' is the blockchain to estimate (BTC or
    # DOGE), 'num_outputs' is the number of outputs per transaction,
    # 'num_concurrent_transactions' is the number of transactions transmitted
    # per block, and, optionally, 'estimate_with_fee' is the fee to calculate
    # with (if None, the current network estimate is used).
    @staticmethod
    def get_estimate(rpc_client, filepath, chain, num_outputs, num_concurrent_transactions, estimate_with_fee):
        from Publication import Publication

        cost = 0.0
        time = None
        ntransactions = 0
        size = None

        # No fee rate was given, so try to get it from the network.
        if (estimate_with_fee is None) or (estimate_with_fee < 0.0):
            print("Getting fee estimate from network...")
            estimate_with_fee = rpc_client.estimatefee(1)
            if estimate_with_fee <= 0.0:
                print("Error: could not get fee estimate from network.  Specify fee manually with --txfee argument.")
                sys.exit(-1)
            else:
                print("Found fee estimate: %f" % estimate_with_fee)


        nbytes = os.stat(filepath).st_size
        if nbytes > 1073741824:
            size = "%s GB" % format(nbytes / 1073741824, '2.1f')
        elif nbytes > 1048576:
            size = "%s MB" % format(nbytes / 1048576, '2.1f')
        elif nbytes > 1024:
            size = "%s KB" % format(nbytes / 1024, '2.1f')
        else:
            size = "%d bytes" % nbytes


        total_num_transactions = math.ceil(nbytes / (num_outputs * Publication.SINGLE_OUTPUT_SIZE))
        num_block_generations = math.ceil(total_num_transactions / num_concurrent_transactions)

        # Another three blocks/transactions are needed for the header,
        # termination, and change transactions.
        num_block_generations += 3
        total_num_transactions += 3

        # For multi-transaction publications, theres a NOOP transaction in the
        # beginning and at the end.
        if num_concurrent_transactions > 1:
            num_block_generations += 2
            total_num_transactions += 2


        # Notes from observation:
        #   Beginning header is 104 bytes, 963 signed (sometimes 739).
        #   Termination header is 148 bytes, 370 signed.
        #   NOOP header is 48 bytes, 391 signed.

        # Through observation, it appears that the file payload accounts for
        # about 2/3rds of the size of the signed transaction.  In other words,
        # when a transaction is carrying 2236 bytes (via 5 outputs), the signed
        # transaction comes to about 3334 bytes (which is about 67%
        # efficiency).  This ratio appears stable even for larger payloads;
        # when transactions carry 4476 bytes (via 10 outputs), the signed
        # transaction size is around 6657 bytes (also about 67% efficient).
        # Hence the overhead multiplier to convert the file size bytes to
        # signed transaction bytes is around 1.5.
        #
        # Also, we will add in the signed message sizes of the beginning header
        # and terminating header.  These were seen to be 963 and 370,
        # respectively, though we will round them up to 1024 and 512.
        tx_bytes = math.ceil(nbytes * 1.5) + 1024 + 512

        # When publishing with multiple transactions, NOOP messages are sent to
        # split the header message into multiple generations.  These NOOPs were
        # observed to be 391 bytes after signing, and we round them up to 512
        # here.  Since this occurs once at the start of publication, and once
        # at the end, this is multiplied by 2.
        if num_concurrent_transactions > 1:
            tx_bytes = tx_bytes + ((num_concurrent_transactions * 512) * 2)

        # Multiply the kilobytes of signed data with the per-KB transaction
        # fee rate.
        transaction_fees = (tx_bytes / 1024) * estimate_with_fee

        # Calculate the transaction fees for Dogecoin differently... because
        # reasons.
        if chain == Publication.BLOCKCHAIN_DOGE:
            # Estimate the final size of each transaction (with sigs included).
            tx_size = (num_outputs * Publication.SINGLE_OUTPUT_SIZE) * 1.5

            # Estimate the fee needed per each transaction.
            fee_per_tx = math.ceil(tx_size / 1024)

            transaction_fees = total_num_transactions * fee_per_tx

        # The estimated cost is the transaction fees, plus the amounts we are
        # sending back and forth.  That is the dust threshold, times the number
        # of outputs per transaction, times the number of concurrent
        # transactions.  This amount is refundable at the end of publication.
        refundable_amount = (num_concurrent_transactions * num_outputs * Publication.DUST_THRESHOLD)
        publication_cost = transaction_fees + refundable_amount

        # The 1.5 multiplier is more accurate for larger file publications, and
        # not so accurate for smaller ones.  So we will scale up the estimate
        # based on file size.
        multiplier = 1.0

        # Smaller than 10KB: 25% increase.
        if nbytes < (1024 * 10):
            multiplier = 1.25

        # Smaller than 100KB: 20% increase.
        elif nbytes < (1024 * 100):
            multiplier = 1.20

        # Smaller than 500KB: 15% increase.
        elif nbytes < (1024 * 500):
            multiplier = 1.15

        # Larger than 500KB: 10% increase.
        else:
            multiplier = 1.10

        publication_cost = publication_cost * multiplier

        # Fees in dogecoin should all be rounded up.
        if chain == Publication.BLOCKCHAIN_DOGE:
            publication_cost = int(math.ceil(publication_cost))

        time = Publication.get_time_estimate(num_block_generations, chain)
        return publication_cost, transaction_fees, refundable_amount, multiplier, time, num_block_generations, size, estimate_with_fee


    # Extracts data from a scriptsig.
    @staticmethod
    def get_data_from_scriptsig(d, scriptsig, has_nonces):
        ptr = 0
        data_blocks = []


        while ptr < len(scriptsig):
            num_bytes = 0
            push_op = struct.unpack('!B', scriptsig[ptr:ptr+1])[0]
            #d("push_op: %d" % push_op)

            # If opcode is 75 or less, this is how many bytes are pushed to the
            # stack.
            if push_op <= 75:
                ptr += 1
                num_bytes = push_op
            # Opcode 76 means the next byte has the length of bytes to push.
            elif push_op == 76:
                ptr += 1
                num_bytes = struct.unpack('<B', scriptsig[ptr:ptr+1])[0]
                ptr += 1
            # Opcode 77 means the next 2 bytes have the length of bytes to
            # push.
            elif push_op == 77:
                ptr += 1
                num_bytes = struct.unpack('<H', scriptsig[ptr:ptr+2])[0]
                ptr += 2
            # With opcode 78, the next 4 bytes have the length.
            elif push_op == 78:
                ptr += 1
                num_bytes = struct.unpack('<I', scriptsig[ptr:ptr+4])[0]
                ptr += 4
            # OP_0 says to push an empty value to the stack.
            elif push_op == 0:
                ptr += 1
                num_bytes = 0
            else:
                d("FAILED TO PARSE SCRIPTSIG")
                return None
        
            if num_bytes > 0:
                data_blocks.append(scriptsig[ptr:ptr+num_bytes])
                ptr += num_bytes

        # The first block has (presumeably) the signature.  The last (second)
        # block has the data we need to extract.
        #last_block = data_blocks[ len(data_blocks) - 1 ]
        last_block = data_blocks[-1]

        # Skip the first byte, which doesn't seem to do anything.
        last_block = last_block[1:]

        # Trim the ending 0xae opcode, if present (OP_MULTISIG).
        if last_block[-1:] == b'\xae':
            last_block = last_block[:-1]

        # Trim off the OP_2-OP_15 opcode too.
        b = struct.unpack('<B', last_block[-1:])[0]
        if b >= 82 and b <= 96:
            last_block = last_block[:-1]

        # Save each data block in a list.  Each is supposed to represent a key.
        # The last_block looks like this:
        # "[size_of_key_1][key_data_1][size_of_key_2][key_data_2]..."
        data_blocks = []
        ptr = 0
        while ptr < len(last_block):
            num_bytes = struct.unpack('!B', last_block[ptr:ptr+1])[0]
            ptr += 1
            data_blocks.append(last_block[ptr+1:ptr + num_bytes])
            ptr += num_bytes

        # Remove the first data block, since this has the legit key instead
        # of data.
        data_blocks = data_blocks[1:]

        # The raw data.
        ret_raw = b''

        # The data with potential nonces stripped out (nonces are only added
        # for plaintext data streams).
        ret_no_nonces = b''

        # If has_nonces is True (i.e.: the file is published in plaintext),
        # we will strip out the nonces.  Otherwise, both return values will
        # be exactly the same.
        nonce_len = 0
        if has_nonces:
            from Publication import Publication
            nonce_len = Publication.NONCE_LEN

        for data_block in data_blocks:
            ret_raw += data_block

        # Strip out any nonces, if necessary.
        if len(ret_raw) > nonce_len:
            ret_no_nonces = ret_raw[nonce_len:]

        return ret_raw, ret_no_nonces


    # Parses the ~/.bitcoin/bitcoin.conf or ~/.dogecoin/dogecoin.conf file for
    # RPC credentials.  Returns the RPC hostname, username, password, and port.
    @staticmethod
    def parse_config_file(conf_file):
        rpchost = 'localhost'
        rpcuser = rpcpassword = rpcport = None

        if not os.path.isfile(conf_file):
            print("Error: could not find config file: %s" % conf_file)
            sys.exit(-1)

        # Read in the entire config file.
        conf_lines = None
        with open(conf_file, 'r') as f:
            conf_lines = f.readlines()

        # Parse each line in the config file.
        for line in conf_lines:
            # Split each line into a key/value pair.
            kv = line.split('=')
            if len(kv) != 2:
                continue

            key = kv[0].strip()
            val = kv[1].strip()

            if key.startswith('rpchost'):
                rpchost = val
            elif key.startswith('rpcuser'):
                rpcuser = val
            elif key.startswith('rpcpassword'):
                rpcpass = val
            elif key.startswith('rpcport'):
                rpcport = int(val)

        return rpchost, rpcport, rpcuser, rpcpass


    # Executes an external program and returns a tuple containing its stdout
    # and stderr bytes.
    @staticmethod
    def exec(args, stdin_str = ''):
        ret_stdout = b''
        ret_stderr = b''
        with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) as process:
            so, se = process.communicate(stdin_str.encode('ascii'))
            ret_stdout += so
            ret_stderr += se

        return ret_stdout, ret_stderr


    # Runs GPG to encrypt or decrypt bytes using key_bytes.
    @staticmethod
    def exec_gpg2(args, file_bytes, key_bytes):

        if len(key_bytes) != 32:
            print("\nERROR: Key length is not 32!: %d\n" % len(key_bytes))
            sys.exit(-1)

        key_base64 = base64.b64encode(key_bytes).decode('ascii') + "\n"

        # Write the plaintext bytes to a temporary file for input.
        # TODO: perhaps write to GPG's stdin?
        fd, temp_input = tempfile.mkstemp()
        os.write(fd, file_bytes)
        os.close(fd)

        # Create an empty temporary file for output.  This reserves the
        # filename so that we can overwrite it with encrypted bytes later and
        # not worry about symlink race attacks.
        fd, temp_output = tempfile.mkstemp()
        os.close(fd)

        # Add the output and input files to the list of arguments.
        args.extend([temp_output, temp_input])

        # Run gpg2.
        so, se = Utils.exec(args, key_base64)

        so = so.decode('utf-8')
        if so != '':
            print("gpg2's stdout: %s" % so)

        se = se.decode('utf-8')
        if se != '':
            print("gpg2's stderr: %s" % se)

        # Get the encrypted bytes
        with open(temp_output, 'rb') as f:
            file_bytes = f.read()

        # Delete the temporary files.
        os.unlink(temp_input)
        os.unlink(temp_output)

        return file_bytes


    # Given a set of encrypted bytes and temporal key, return the plaintext
    # bytes.
    @staticmethod
    def decrypt(file_bytes, temporal_key):
        return Utils.exec_gpg2(['gpg2', '-q', '--batch', '--yes', '--passphrase-fd=0', '-o'], file_bytes, temporal_key)


    # Generates a random temporal key, encrypts the file_bytes argument,
    # and returns the encrypted bytes and key.  The output is only 79-82 bytes
    # larger than the input.
    @staticmethod
    def encrypt(file_bytes):
        # Generate a key.  The docs for os.urandom() say that this is
        # sufficient for cryptographic key material.  The key bytes are
        # converted to alphanumerics with Base64.
        key_bytes = os.urandom(32)

        return Utils.exec_gpg2(['gpg2', '-q', '--batch', '--yes', '--passphrase-fd=0', '--cipher-algo=AES256', '--digest-algo=SHA512', '--compress-algo=none', '--compress-level=0', '--symmetric', '-o'], file_bytes, key_bytes), key_bytes
