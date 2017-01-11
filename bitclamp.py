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

import argparse, atexit, pickle, signal, sys, threading, time

if sys.version_info.major < 3:
    print('Error: you must invoke this script with python3, not python.')
    exit(-1)

from BlockListener import *
from Publication import *
from RPCClient import *
from Utils import *

cleanup_lock = None
publication = None
daemon_proc = None
rpc_client = None

# Prints a message if in debug mode.
def d(s):
    if debug:
        print(s)


# Prints a message if in verbose mode.
def v(s):
    if verbose:
        print(s)


def setup_block_listener_and_daemon(rpc_client, spawn_daemon, daemon_name, regtest, testnet, change_address):
    proc = None

    block_listener = BlockListener(d, rpc_client)
    block_listener.start_listener()
    v('Started BlockListener on port %d' % block_listener.port)

    # If we were told to spawn our own daemon...
    if spawn_daemon:
        blockclient_py = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'BlockClient.py')

        args = [daemon_name, '-daemon', '-txindex', '-listen=0', '-blocknotify=python3 %s localhost %d' % (blockclient_py, block_listener.port)]

        if regtest:
            args.append('-regtest')
            args.append('-addnode=localhost')
        elif testnet:
            args.append('-testnet')
            args.append('-addnode=localhost')

        d('Executing: %s' % ' '.join(args))

        # Launch the daemon.
        proc = subprocess.Popen(args, bufsize=0, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        if proc is None:
            print('Error: failed to run %s!  Terminating.' % daemon_name)
            exit(-1)

        # Wait up to 10 minutes for the daemon to fully initialize and begin
        # responding to RPC calls.
        block_count = 0
        seconds = 0
        while seconds < 600: # 10 minutes
            time.sleep(5)
            seconds += 5

            try:
                block_count = rpc_client.getblockcount()
            except Exception as e:
                print(str(e))
                pass

            if block_count > 0:
                break

            if (seconds % 15) == 0:
                print('Waiting for %s to finish initializing (%d minutes, %d seconds)...' % (daemon_name, (seconds / 60), (seconds % 60)))

        # If the daemon still isn't responding to RPC calls, its time to give
        # up.
        if block_count == 0:
            print('%s failed to initialize within 10 minutes.  Consider using --daemon=existing.  Terminating.' % daemon_name)
            exit(-1)

        d('%s initialized after %d seconds.' % (daemon_name, seconds))

        # Wait for the daemon to synchronize the blockchain since it just
        # started up.  We call the getblockchaininfo() RPC function to get
        # the total number of known blocks and latest obtained block.  When
        # the two are within 5 blocks of each other, we consider the daemon
        # synced.
        #
        # Because new blocks may become known as synchronization occurs, we
        # will actually do three passes.
        v('Waiting for daemon to synchronize blockchain...')
        sync_start_time = time.time()
        for i in range(0, 3):
            d('Pass #%d...' % (i + 1))
            blockchaininfo = rpc_client.getblockchaininfo()
            latest_block = blockchaininfo['headers']
            current_block = blockchaininfo['blocks']

            block_diff = latest_block - current_block

            # Normalize the Dogecoin block difference to that of Bitcoin.
            if chain == Publication.BLOCKCHAIN_DOGE:
                block_diff = block_diff / 10

            # Sleep for 1/3rd of the amount of blocks missing, in seconds
            # (i.e.: if we are 30 blocks behind, sleep 10 seconds).
            while block_diff > 5:
                seconds_to_sleep = 60
                if block_diff < 60:
                    seconds_to_sleep = 20
                elif block_diff < 30:
                    seconds_to_sleep = 10
                elif block_diff < 15:
                    seconds_to_sleep = 5

                # Sleep only 1 second if we are in a test environment.
                if regtest or testnet:
                    seconds_to_sleep = 1

                time.sleep(seconds_to_sleep)

                # Re-calculate the block difference.
                current_block = rpc_client.getblockcount()
                block_diff = latest_block - current_block

                # Normalize the Dogecoin block difference to that of Bitcoin.
                if chain == Publication.BLOCKCHAIN_DOGE:
                    block_diff = block_diff / 10

                d('Latest block: %d; current_block: %d; Normalized difference: %d; Syncing for %d secs' % (latest_block, current_block, block_diff, time.time() - sync_start_time))

    else:
        print("\n--> BlockListener is now listening on port %d.  Configure %s to connect back to this port, and publication can begin.  In the file that its BlockClient parses, add the following on a line by itself:\n\n\tlocalhost %d\n" % (block_listener.port, daemon_name, block_listener.port))
        print("Do this BEFORE you send the funds to the publication address!\n")

    # Ensure that the BlockListener is properly responding to requests.
    d('Checking if BlockListener is reachable...')
    success = False
    while success is False:
        emesg = ''
        try:
            s = socket.socket(socket.AF_INET, socket. SOCK_STREAM)
            s.settimeout(10)
            s.connect(('localhost', block_listener.port))
            if s.send(b'J') == 1 and s.recv(1) == b'T':
                success = True
                d('BlockListener successfully pinged.')
        except Exception as e:
            emesg = str(e)

        if not success:
            v('Failed to send and receive ping from BlockListener. %s' % emesg)
            time.sleep(1)


    # Now that the daemon is properly synchronized, begin processing blocks.
    block_listener.begin_processing()

    # Validate the change address.
    is_valid = rpc_client.validateaddress(change_address)['isvalid']
    if is_valid != True:
        print('Error: %s is not a valid address!' % change_address)
        sys.exit(-1)

    return block_listener, proc


# The signal function for this program.  Responsible for saving the state of
# an ongoing publication whenever the user presses control-C (SIGINT) or SIGTERM
# is received.
def signal_handler(signum, frame):
    atexit.unregister(exit_handler)
    cleanup()
    exit(0)


# Called when the program terminates.
def exit_handler():
    cleanup()


def cleanup():
    cleanup_lock.acquire()

    global daemon_proc, rpc_client, publication

    # If we spawned a daemon, we're responsible for stopping it.  Since this
    # can take some time, we do this first (asynchronously), then check on it
    # after we dump state information below.
    if (daemon_proc is not None) and (rpc_client is not None):
        rpc_client.stop()
        v('Instructed daemon to terminate.')


    # If the publication is not complete, and funds were received, save its
    # state.
    if publication is not None:
        if not publication.complete:
            v('Because publication is not complete, writing state file to %s...' % publication.state_file)
            with open(publication.state_file, 'wb') as f:
                pickle.dump(publication, f, pickle.HIGHEST_PROTOCOL)

        # If the publication is complete, delete its state file.
        elif os.path.exists(publication.state_file):
            v('Because publication is complete, deleting state file: %s' % publication.state_file)
            os.unlink(publication.state_file)

    # Wait up to 30 seconds for the daemon to shut down.
    if (daemon_proc is not None) and (rpc_client is not None):
        retcode = None
        try:
            v('Waiting up to 30 seconds for daemon to terminate...')
            retcode = daemon_proc.wait(30)
            v('Daemon terminated with return code %d.' % retcode)
        except subprocess.TimeoutExpired as e:
            print('WARNING: bitcoind/dogecoind did not terminate after 30 seconds.  You should manually attempt to shut it down *gracefully*.  Blockchain corruption can occur if done abruptly.')

    daemon_proc = None
    rpc_client = None
    publication = None
    cleanup_lock.release()


cleanup_lock = threading.Lock()
parser = argparse.ArgumentParser()

# (Mostly) required arguments.
parser.add_argument('--file', help='the file to publish [required]')
parser.add_argument('--txfee', help='the transaction fee per KB to use [required]', default=-1.0)
parser.add_argument('--change', help='address to send the leftover change to [required]')
parser.add_argument('--daemon', help='when set to "spawn", a new bitcoind/dogecoind is started to publish with, then later terminated when finished.  If set to "existing", rely on an already-running bitcoind/dogecoind instance. [required]')


# Estimation of cost and time for publication.
parser.add_argument('--estimate', help='estimate the cost to publish the file', action='store_true')

# Publication options.
parser.add_argument('--noutputs', help='number of outputs per transaction (default: 5)', default=5)
parser.add_argument('--ntransactions', help='number of concurrent transactions (default: 1).  Not useful for BTC publishing, but very, very useful to increase for DOGE.', default=1)
parser.add_argument('--chain', help='the blockchain to use ("btc" or "doge"; default: "btc")', default='btc')
parser.add_argument('--name', help='the filename to publish as.  If unspecified, the filename in --file is used.  To omit the filename in the publication, use "" here.')
parser.add_argument('--description', help='an optional description of this file', default='')
parser.add_argument('--content-type', help='the type of file this is.  Acceptable values: document, picture, sound, video, sourcecode, digitalsignature, archive, undefined.  If not specified, the type will try to be auto-detected from its file extension.', default="auto")
parser.add_argument('--compression', help='the type of compression to use.  Acceptable values: none, zip, gzip, bzip2, xz, lzma, 7zip.  If not specified, all compression methods will be tried and the one that yields the smallest file selected.', default="auto")
parser.add_argument('--no-crypto', help='this disables the default temporal encryption that is done on the file before publishing.  Enabling this option causes the file to be published in plaintext.  This is useful if you want parts of the file to be immediately readable (i.e.: if you are in a high-pressure situation and you want to publish as much as possible before being shut down).  Otherwise, with temporal encryption enabled (the default), the file is completely unreadable until ALL of it is published.', action='store_true')
parser.add_argument('--deadman-switch-save', help='enable deadman switch publication mode.  This publishes an encrypted file without automatically including the key.  The key can later be published if a secret check-in process is not completed (which must be implemented manually).  Hence, the user gains insurance against being arrested and/or killed (as this would prevent the secret check-in process from being completed in the time interval required).  For more information, see the DEADMAN_SWITCH_README.txt.  This option requires a file path to write the key information to.')
parser.add_argument('--deadman-switch-publish', help='publishes the key for a file already in the blockchain.  Takes the path of the file created with --deadman-switch-save as the argument.  For more information, see the DEADMAN_SWITCH_README.txt.')

# Load state
parser.add_argument('--restore', help='restore an interrupted publication from a *.state file.')

# Debugging options.
parser.add_argument('-v', '--verbose', help='enable verbose messages', action='store_true')
parser.add_argument('-d', '--debug', help='enable debugging messages', action='store_true')
parser.add_argument('--testnet', help='use the test network instead of production network (mainnet)', action='store_true')
parser.add_argument('--regtest', help='enable regression test mode (for debugging & development only)', action='store_true')

# Hidden options for unit testing.
parser.add_argument('--unittest-publication-address', help=argparse.SUPPRESS, default=None)

args = vars(parser.parse_args())

# Read command line arguments.
verbose = args['verbose']
debug = args['debug']
filepath = args['file']
num_outputs = int(args['noutputs'])
num_transactions = int(args['ntransactions'])
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
nocrypto = args['no_crypto']
restore = args['restore']
daemon = args['daemon']
deadman_switch_save = args['deadman_switch_save']
deadman_switch_publish = args['deadman_switch_publish']

unittest_publication_address = args['unittest_publication_address']


# Debug mode implies verbose mode.
if debug:
    verbose = True


# --daemon must be specified unless we are estimating cost & time.
if daemon not in ('spawn', 'existing') and not estimate:
    print('Error: --daemon flag must be set to either "spawn" or "existing".')
    exit(-1)


# If the user chose to restore the state of a publication, handle that
# immediately.
if restore is not None:
    publication = None
    with open(restore, 'rb') as f:
        publication = pickle.load(f)

    # Register the state-saving signal handlers.
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    atexit.register(exit_handler)

    v("Restoring publication:")
    v(publication)

    rpc_client = RPCClient.init_from_config_file('btc' if publication.blockchain == Publication.BLOCKCHAIN_BTC else 'doge')

    block_listener, daemon_proc = setup_block_listener_and_daemon(rpc_client, daemon == 'spawn', Utils.get_daemon_name(publication.blockchain), regtest, testnet, publication.change_address)

    publication.block_listener = block_listener
    publication.rpc_client = rpc_client
    publication.set_unittest_publication_address(unittest_publication_address)

    # Update the number of confirmations for all sent transactions.
    v("Updating confirmations...")
    publication.update_confirmations(False, True)

    # Go through the latest TxRecords.  If they have zero confirmations,
    # re-transmit them and wait for at least one confirmation.
    txrecords_to_retransmit = []
    for generation in range(0, len(publication.txrecords)):
        previous_txrecord = publication.txrecords[generation][-2]
        txrecord = publication.txrecords[generation][-1]
        if txrecord.get_confirmations() == 0:
            txrecords_to_retransmit.append(([previous_txrecord], [txrecord]))

    if len(txrecords_to_retransmit) > 0:
        v("Re-transmitting %d TxRecords..." % len(txrecords_to_retransmit))
        publication.transmit_txrecords(txrecords_to_retransmit)

    # Check if the publication is already complete.
    if publication.complete:
        print("Publication complete!")

        # The exit handler will delete the state file.
        sys.exit(0)

    # Now that all the latest TxRecords have at least one confirmation,
    # continue publishing the rest of the file.
    publication.resume()
    sys.exit(0)


# Validate the --chain arg.
if chain.lower() == 'btc':
    chain = Publication.BLOCKCHAIN_BTC
elif chain.lower() == 'doge':
    chain = Publication.BLOCKCHAIN_DOGE
else:
    print("Invalid chain: %s.  Valid values are 'btc' or 'doge'." % chain)
    sys.exit(-1)

# Get the name of the daemon program for this chain (i.e.: 'bitcoind' or
# 'dogecoind').
daemon_name = Utils.get_daemon_name(chain)

# Create the RPC client from the local config file (bitcoin.conf/dogecoin.conf).
rpc_client = RPCClient.init_from_config_file('btc' if chain == Publication.BLOCKCHAIN_BTC else 'doge')


# --testnet and --regtest are mutually exclusive.
if testnet and regtest:
    print("Error: --testnet and --regtest may not be used simultaneously.")
    sys.exit(-1)


# I've always sneered when other developers used the term "self-documenting
# code", but maybe that can be a thing after all...
if (num_outputs < 1) or (num_outputs > 20):
    print("Error: the number of outputs must be between 1 and 20.")
    sys.exit(-1)

# More self-documenting code.  :D
if (num_transactions < 1) or (num_transactions > 100):
    print("Error: the number of transactions must be between 1 and 100.")
    sys.exit(-1)

# If --estimate was given, but no file was specified...
if estimate is True and filepath is None:
    print("Error: to estimate publication figures, the file must be specified (--file).")
    sys.exit(-1)

# Check if we can communicate with bitcoind/dogecoind.
is_daemon_reachable = False
connection_count = 0
try:
    # The integer parsing might throw an exception on error.
    connection_count = rpc_client.getconnectioncount()
    is_daemon_reachable = True
except Exception as e:
    if daemon == 'existing':
        print('Error while testing connection to %s.  Check settings in %s file and try again.  Exception message: %s' % (daemon_name, rpc_client.config_file, str(e)))
        exit(-1)
    else:
        pass

# If the user indicated that we should spawn our own daemon, but one is already
# reachable, then print a warning, switch to daemon existing mode, and
# continue.
if daemon == 'spawn' and is_daemon_reachable:
    print("\nWARNING: --daemon=spawn was specified, yet %s happens to be reachable (it is connected to %d peers).  Switching to --daemon=existing and continuing.  If this is not desired, terminate the program now, shut down %s, and try again.\n" % (daemon_name, connection_count, daemon_name))
    daemon = 'existing'

# If the daemon isn't managed by us, make sure that its connected to at least
# one peer.
if daemon == 'existing' and (connection_count < 1):
    print('%s is not connected to any peers.  Check its connection settings and try again.' % daemon_name)
    sys.exit(-1)

# If we are publishing a deadman switch key, skip content type and compression
# option parsing.
if deadman_switch_publish is None:

    # Ensure that the --content-type argument is valid and get its
    # Publication.CONTENT_TYPE_* ID.
    content_type_const = Publication.get_content_type_const(content_type)
    if content_type_const is False:
        print("Error: %s is not a valid content type." % content_type)
        sys.exit(-1)

    # Ensure that the --compression argument is valid and get its
    # Publication.COMPRESSION_TYPE_* ID.
    compression_type_const = Publication.get_compression_type_const(compression)
    if compression_type_const is False:
        print("Error: %s is not a valid compression type." % compression)
        sys.exit(-1)

# If --estimate was given, and the user gave the file to estimate with...
if estimate is True:
    publication_amount, transaction_fees, refundable_amount, multiplier, time, nblockgens, size, fee_rate = Utils.get_estimate(rpc_client, filepath, chain, num_outputs, num_transactions, txfee)
    chainstr = "BTC" if chain == Publication.BLOCKCHAIN_BTC else "DOGE"
    print("To publish %s (%s) on the %s network with a transaction fee rate of %.8f, the amount needed to begin publishing is %.8f %s.  Of this figure, %.8f will be lost to transaction fees, and %.8f will be sent between transactions.  Based on the size of the file, an extra %d%% is added to account for variability in the transaction sizes (larger files will have less added than smaller ones).  Because any and all unused funds are refunded upon completion, the true publication cost should be closer to the transaction fee cost (%.8f).  With %d concurrent transactions, and %d outputs per transaction, publication will require at least %d blocks, or at least %s.\n\nNote that this is accurate under optimal network conditions.  Real-world conditions may vary greatly." % (filepath, size, chainstr, fee_rate, publication_amount, chainstr, transaction_fees, refundable_amount, round(((multiplier - 1) * 100)), transaction_fees, num_transactions, num_outputs, nblockgens, time))
    sys.exit(0)

# To publish, --txfee must be given.
if (txfee is None) or (txfee < 0):
    print("Error: --txfee must be specified!")
    sys.exit(-1)

# An address for any leftover change is mandatory when publishing.
if (change_address is None) or (change_address == ''):
    print("Error: --change must be specified!")
    sys.exit(-1)

# If the user wants to publish a deadman switch key, lets handle that now.
if deadman_switch_publish is not None:

    if filepath is not None:
        print("Warning: --file and --deadman-switch-publish are incompatible.  Ignoring the --file argument and continuing...")

    block_listener, daemon_proc = setup_block_listener_and_daemon(rpc_client, daemon == 'spawn', daemon_name, regtest, testnet, change_address)

    publication = Publication(rpc_client, block_listener, deadman_switch_publish, chain, testnet or regtest, txfee, change_address, debug, verbose, unittest_publication_address)

    publication.begin()
    sys.exit(0)

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

deadman_switch = None
if nocrypto and (deadman_switch_save is not None):
    print("Error: --no-crypto conflicts with --deadman-switch-save.")
    sys.exit(-1)

if (deadman_switch_save is not None) and os.path.isfile(deadman_switch_save):
    print("Error: deadman switch key path already exists: %s" % deadman_switch_save)
    sys.exit(-1)



# Register signal handlers.  This will save the state so that publication may
# be fully restored and resumed later.
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
atexit.register(exit_handler)

block_listener, daemon_proc = setup_block_listener_and_daemon(rpc_client, daemon == 'spawn', daemon_name, regtest, testnet, change_address)

publication = Publication(rpc_client, block_listener, filepath, content_type_const, compression_type_const, filename, file_description, nocrypto, deadman_switch_save, chain, testnet or regtest, num_outputs, num_transactions, txfee, change_address, debug, verbose, unittest_publication_address)

publication.begin()
sys.exit(0)
