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

import argparse, atexit, pickle, sys

from Publication import *
from RPCClient import *


# Prints a message if in debug mode.
def d(s):
    if debug:
        print(s)


# The exit function for this program.  Responsible for saving the state of
# an ongoing publication.
def exit_handler(publication):
    # If the publication is not complete, and funds were received, save its
    # state.
    if not publication.complete and publication.received_funds:
        with open(publication.state_file, 'wb') as f:
            pickle.dump(publication, f, pickle.HIGHEST_PROTOCOL)

    # If the publication is complete, delete its state file.
    elif os.path.exists(publication.state_file):
        os.unlink(publication.state_file)


parser = argparse.ArgumentParser()

# (Mostly) required arguments.
parser.add_argument('--file', help='the file to publish (required)')
parser.add_argument('--txfee', help='the transaction fee per KB to use (required)', default=-1.0)
parser.add_argument('--change', help='address to send the leftover change to (required)')

# Estimation of cost and time for publication.
parser.add_argument('--estimate', help='estimate the cost to publish the file', action='store_true')

# Publication options.
parser.add_argument('--noutputs', help='number of outputs per transaction (default: 5)', default=5)
parser.add_argument('--chain', help='the blockchain to use ("btc" or "doge"; default: "btc")', default='btc')
parser.add_argument('--name', help='the filename to publish as.  If unspecified, the filename in --file is used.  To omit the filename in the publication, use "" here.')
parser.add_argument('--description', help='an optional description of this file', default='')
parser.add_argument('--content-type', help='the type of file this is.  Acceptable values: document, picture, sound, video, sourcecode, digitalsignature, archive, undefined.  If not specified, the type will try to be auto-detected from its file extension.', default="auto")
parser.add_argument('--compression', help='the type of compression to use.  Acceptable values: none, zip, gzip, bzip2, xz, lzma, 7zip.  If not specified, all compression methods will be tried and the one that yields the smallest file selected.', default="auto")
parser.add_argument('--no-crypto', help='this disables the default temporal encryption that is done on the file before publishing.  Enabling this option causes the file to be published in plaintext.  This is useful if you want parts of the file to be immediately readable (i.e.: if you are in a high-pressure situation and you want to publish as much as possible before being shut down).  Otherwise, with temporal encryption enabled (the default), the file is completely unreadable until ALL of it is published.', action='store_true')
parser.add_argument('--no-hash', help='do not store the SHA256 hash of the bytes to publish in the header.  This may only be used in conjunction with --no-crypto.  If, say, you choose to publish the file in plaintext, you may hide the plaintext\'s hash using this option.  This may protect you while the publication process completes.  Otherwise, if the default temporal encryption is used, this hash is calculated over the encrypted bytes, which is safe to make public know even if the plaintext is known ahead of time.', action='store_true')
#parser.add_argument('--deadman-switch-save', help='enable deadman switch publication mode.  This publishes an encrypted file without automatically including the key.  The key can later be published if a secret check-in process is not completed (which must be implemented manually).  Hence, the user gains insurance against being arrested and/or killed (as this would prevent the secret check-in process from being completed in the time interval required).  For more information, see the DEADMAN_SWITCH_README.txt.  This option requires a file path to write the key information to.')
#parser.add_argument('--deadman-switch-publish', help='publishes the key for a file already in the blockchain.  Takes the path of the file created with --deadman-switch-save as the argument.')

# Load state
parser.add_argument('--restore', help='restore an interrupted publication from a *.state file.')

# Debugging options.
parser.add_argument('-v', '--verbose', help='enable verbose messages', action='store_true')
parser.add_argument('-d', '--debug', help='enable debugging messages', action='store_true')
parser.add_argument('--testnet', help='use the test network instead of production network (mainnet)', action='store_true')
parser.add_argument('--regtest', help='enable regression test mode (for debugging & development only)', action='store_true')

# RPC client options.
parser.add_argument('--rpchost', help='the hostname of the Bitcoin RPC server to use', default='')
parser.add_argument('--rpcport', help='the port of the Bitcoin RPC server to use', default=0)
parser.add_argument('--rpcuser', help='the username to authenticate as against the Bitcoin RPC server', default='')
parser.add_argument('--rpcpass', help='the password to authenticate as against the Bitcoin RPC server', default='')

args = vars(parser.parse_args())

# Read command line arguments.
verbose = args['verbose']
debug = args['debug']
filepath = args['file']
num_outputs = int(args['noutputs'])
chain = args['chain']
testnet = args['testnet']
regtest = args['regtest']

txfee = float(args['txfee'])
change_address = args['change']
filename = args['name']
file_description = args['description']
estimate = args['estimate']
content_type = args['content_type']
compression = args['compression']
nohash = args['no_hash']
nocrypto = args['no_crypto']
restore = args['restore']
#deadman_switch_save = args['deadman_switch_save']
#deadman_switch_publish = args['deadman_switch_save']


xrpchost = args['rpchost']
xrpcport = int(args['rpcport'])
xrpcuser = args['rpcuser']
xrpcpass = args['rpcpass']


# Debug mode implies verbose mode.
if debug:
    verbose = True


# If the user chose to restore the state of a publication, handle that
# immediately.
if restore is not None:
    publication = None
    with open(restore, 'rb') as f:
        publication = pickle.load(f)

    # Register the state-saving exit handler.
    atexit.register(exit_handler, publication)

    if verbose:
        d("Restoring publication:")
        d(publication)
        d("\nUpdating confirmations...")

    # Update the number of confirmations for all sent transactions.
    publication.update_confirmations(True)
    if publication.complete:
        print("Publication complete!")

        # The exit handler will delete the state file.
        sys.exit(0)

    txrecord = publication.txrecords[-1]
    d("Last TxRecord: %s" % txrecord)

    if txrecord.get_confirmations() == 0:
        if not publication.wait_for_confirmation(txrecord, None):
            print("wait_for_confirmation() failed!")


    continue_flag = True
    while continue_flag:
        next_txrecord = publication.resume(txrecord)
        if not publication.wait_for_confirmation(next_txrecord, None):
            print("wait_for_confirmation() failed!")

        txrecord = next_txrecord

        if publication.change_sent is True:
            next_txrecord.set_last_record()
            continue_flag = False


    print("Publication complete!")
    sys.exit(0)


# Validate the --chain arg.
if chain.lower() == 'btc':
    chain = Publication.BLOCKCHAIN_BTC
elif chain.lower() == 'doge':
     chain = Publication.BLOCKCHAIN_DOGE   
else:
    print("Invalid chain: %s.  Valid values are 'btc' or 'doge'." % chain)
    sys.exit(-1)


rpchost = xrpchost if xrpchost != '' else 'localhost'
rpcport = xrpcport
rpcuser = xrpcuser
rpcpass = xrpcpass

rpc_client = RPCClient(rpchost, rpcport, rpcuser, rpcpass)


# --testnet and --regtest are mutually exclusive.
if testnet and regtest:
    print("Error: --testnet and --regtest may not be used simultaneously.")
    sys.exit(-1)


# I've always sneered when other developers used the term "self-documenting
# code", but maybe that can be a thing after all...
if (num_outputs < 1) or (num_outputs > 20):
    print("Error: the number of outputs must be between 1 and 20.")
    sys.exit(-1)


# If --estimate was given, but no file was specified...
if estimate is True and filepath is None:
    print("Error: to estimate publication figures, the file must be specified (--file).")
    sys.exit(-1)


# Make sure that we can communicate with the Bitcoin server.
try:
    # The integer parsing might throw an exception on error.
    connection_count = rpc_client.getconnectioncount()
except Exception as e:
    print(e)
    print("Error while testing connection to Bitcoin server.  Check settings (--rpcuser, --rpcpass, --rpchost, and/or bitcoin.conf file) and try again.")
    sys.exit(-1)

# Make sure that the server is connected to at least one peer.
if connection_count < 1:
    print("The Bitcoin server is not connected to any peers.  Check its connection settings and try again.")
    sys.exit(-1)

# Ensure that the --content-type argument is valid.
ctypes = {v: k for k, v in Publication.CONTENT_TYPE_MAP.items()}
if content_type not in ctypes:
    print("Error: %s is not a valid content type." % content_type)
    sys.exit(-1)

content_type_const = ctypes[content_type]

# Ensure that the --compression argument is valid.
ctypes = {v: k for k, v in Publication.COMPRESSION_TYPE_MAP_STR.items()}
if compression not in ctypes:
    print("Error: %s is not a valid compression type." % compression)
    sys.exit(-1)

compression_const = ctypes[compression]


# If --estimate was given, and the user gave the file to estimate with...
if estimate is True:
    cost, time, ntxs, size, fee = Utils.get_estimate(rpc_client, filepath, chain, num_outputs, txfee)
    chainstr = "BTC" if chain == Publication.BLOCKCHAIN_BTC else "DOGE"
    print("To publish %s (%s) on the %s network with a transaction fee of %f, the cost will be %f %s.  The %d transactions will take about %s." % (filepath, size, chainstr, fee, cost, chainstr, ntxs, time))

    sys.exit(0)

# To publish, --txfee must be given.
if txfee is None or txfee < 0:
    print("Error: --txfee must be specified!")
    sys.exit(-1)

# An address for any leftover change is mandatory when publishing.
if change_address is None or change_address is "":
    print("Error: --change-address must be specified!")
    sys.exit(-1)

# Validate the change address.
is_valid = rpc_client.validateaddress(change_address)['isvalid']
if is_valid != True:
    print("Error: %s is not a valid address!" % change_address)
    sys.exit(-1)


if filepath is None:
    print("Error: the file to publish (--file) is required.")
    sys.exit(-1)

# If the user did not specify an explicit filename to use, use the base name
# of the file (i.e.: the full file name, minus its absolute path).
if filename is None:
    filename = os.path.basename(filepath)

# The internal file name field cannot be greater than 128 characters.  123 is
# the max here, because up to 5 characters will be appended automatically if
# LZMA compression is used (i.e.: the ".lzma" extension).
if len(filename) > 123:
    print("Error: file name (--name) cannot be greater than 123 characters.")
    sys.exit(-1)

# Make sure the description is 128 characters or less.
if len(file_description) > 128:
    print("Error: file description (--description) cannot be greater than 128 characters.")
    sys.exit(-1)

# If temporal encryption is still enabled, but the user specified --no-hash,
# this is an error.  It doesn't make sense to suppress the hash of the
# encrypted file.
if not nocrypto and nohash:
    print("Error: it does not make sense to specify --no-hash without --no-crypto.  NOTE: Before specifying --no-crypto, be SURE you understand what that means!")
    sys.exit(-1)


deadman_switch = None
#if nocrypto and deadman_switch_save is not None:
#    print("Error: --no-crypto conflicts with --deadman-switch-save.")
#    sys.exit(-1)

#if os.path.isfile(deadman_switch_save):
#    print("Error: deadman switch key path already exists: %s" % deadman_switch_save)
#    sys.exit(-1)


publication = Publication(rpc_client, filepath, content_type_const, compression_const, filename, file_description, nocrypto, nohash, deadman_switch, chain, testnet or regtest, num_outputs, txfee, change_address, debug, verbose)

# Register an exit handler function with a reference to this Publication.  This
# will save the state so that it may be fully restored and resumed later.
atexit.register(exit_handler, publication)

publication.begin()
sys.exit(0)
