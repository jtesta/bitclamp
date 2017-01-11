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


# Utility functions for the unit test framework.

import fcntl, hashlib, math, os, pickle, subprocess, time

# A list of temporary files created by make_temp_file().
temp_files = []

# The full path to the bitclamp.py script.
bitclamp_py = None

# The full path to the bitclamp_extracterizer.py script.
bitclamp_extracterizer_py = None

# The temp directory inside the writer's home directory.
writer_tempdir = None

# The full path to the file used by the writer's BlockClient which holds the
# active BlockListeners.
writer_block_listener_file = None

# The output directory inside the reader's home directory.
reader_outputdir = None

# The partial directory inside the reader's output directory.
reader_partialdir = None

# The reader's lockfile.
reader_lockfile = None

# The address to send all change to.
change_address = None

# The current chain, in string form.  This is either 'btc' or 'doge'.
chain_str = None

# True if we are using the BTC chain, otherwise we are using DOGE.
chain_btc = None

# If true, Bitcoin Classic is in use, otherwise Bitcoin Core.
btc_classic = True

# The cli program to use.  'bitcoin-cli' for BTC, and 'dogecoin-cli' for DOGE.
cli = None

# The usernames of the writer and reader users, respectively.
user_writer = None
user_reader = None

# The full path to the SQLite3 database.
sqlite3_file = None


# Removes any leftover files from a previous publication in the output
# directory, and returns two new temporary files.
def begin_test():
  # Delete all files in the output directory that isn't the log file.
  for f in os.listdir(reader_outputdir):
    full_path = os.path.join(reader_outputdir, f)
    if os.path.isfile(full_path) and f != 'log.txt' and f != 'lockfile' and f != 'bitclamp_sqlite.db':
      os.remove(full_path)

  # Delete all files in the partial/ sub-directory.
  if os.path.isdir(reader_partialdir):
    for f in os.listdir(reader_partialdir):
      os.remove(os.path.join(reader_partialdir, f))

  # Delete all *.state files.
  writer_home_dir = os.path.expanduser('~%s' % user_writer)
  for f in os.listdir(writer_home_dir):
    if f.endswith('.state'):
      os.remove(os.path.join(writer_home_dir, f))

  return make_temp_file(), make_temp_file()


# Gets the SHA512 hash of the target file.
def calc_sha512(file_path):
  data = b''
  with open(file_path, 'rb') as f:
    data = f.read()

  return hashlib.sha512(data).hexdigest()


# Deletes all temporary files created by make_temp_file().
def clean_temp_files():
  for temp_file in temp_files:
    if os.path.isfile(temp_file) and (not os.path.islink(temp_file)):
      os.remove(temp_file)


# Get a list of all filenames in the database.  This is with respect to the
# last time the unit tests were run.
def database_get_file_list():
  import sqlite3

  ret = []
  db = sqlite3.connect(sqlite3_file)
  for row in db.execute('SELECT filename, initial_block_num, final_block_num, is_deadman_switch_file, file_hash FROM publications WHERE is_deadman_switch_key=0'):
    ret.append((row[0], row[1], row[2], row[3], row[4]))

  db.close()
  return ret


# Given the filename of a publication, extract its description from the
# database.
def database_get_file_description(filename):
  import sqlite3

  db = sqlite3.connect(sqlite3_file)
  cursor = db.execute('SELECT description FROM publications WHERE filename=?', (filename,))
  ret = cursor.fetchone()[0]
  db.close()

  return ret


# Given the filename of a publication, extract its SHA256 hash from the
# database.
def database_get_file_hash(filename):
  import sqlite3

  db = sqlite3.connect(sqlite3_file)
  cursor = db.execute('SELECT file_hash FROM publications WHERE filename=?', (filename,))
  ret = cursor.fetchone()[0]
  db.close()

  return ret


# Retrieves the first block number of content in the database.  This is with
# respect to the last time the unit tests were run.
def database_get_first_block_num():
  import sqlite3

  db = sqlite3.connect(sqlite3_file)
  cursor = db.execute('SELECT MIN(initial_block_num) FROM publications')
  ret = cursor.fetchone()[0]
  db.close()

  return ret


# Check if an output file was properly created, and if its SHA-512 hash matches
# the expected value.  Returns True, otherwise False.
def does_output_file_match(filename, expected_hash):
  output_file = os.path.join(reader_outputdir, filename)
  if not os.path.isfile(output_file):
    print("Output file %s does not exist!" % output_file)
    return False

  calculated_hash = calc_sha512(output_file)

  if calculated_hash != expected_hash:
    print("Calculated and expected SHA-512 hashes for %s do not match!" % output_file)
    print("Calculated: %s" % calculated_hash)
    print("Expected:   %s" % expected_hash)
    return False

  return True


# Executes a program asynchronously.  Returns a process handle and file handle
# to its (merged) stdout and stderr streams.
def exec_async(user, arg_str, output_file):
  args = ['su', '-', user, '-c', arg_str]

  output_fd = open(output_file, 'w+b')
  process = subprocess.Popen(args, bufsize=0, stdout=output_fd, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
  return process, output_fd


# Executes a program and waits for it to finish before returning its stdout and
# stderr.
def exec_wait(user, arg_str, stdin_str = ''):
  args = ['su', '-', user, '-c', arg_str]

  ret_stdout = b''
  ret_stderr = b''
  with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE) as process:
    so, se = process.communicate(stdin_str.encode('ascii'))
    ret_stdout += so
    ret_stderr += se

  return ret_stdout, ret_stderr


# Executes a program as the reader user, and waits for it to finish before
# returning its stdout and stderr.
def exec_wait_reader(arg_str, stdin_str = ''):
  return exec_wait(user_reader, arg_str, stdin_str)


# Generates blocks as the writer user.  If wait_for_mempool is True, then
# it will wait up to 1 second until at least one transaction is found in the
# mempool (after the time has elapsed, the block(s) will be generated
# regardless).
def generate_blocks(num_blocks, wait_for_mempool):

  if wait_for_mempool:
    so = ''
    timeout = 0.0
    while (len(so) < 64) and timeout < 1:
      so, se = exec_wait(user_writer, '/bin/bash -c "%s getrawmempool"' % cli)

      # If nothing is in the mempool, then sleep 100ms and loop.
      if len(so) < 64:
        time.sleep(0.1)
        timeout += 0.1

  exec_wait(user_writer, '/bin/bash -c "%s generate %d \$PUBKEY"' % (cli, num_blocks))


# Given a filename, returns its full path in the reader's partial output
# directory.
def get_partial_file_path(filename):
  return os.path.join(reader_partialdir, filename)


# Given a filename, returns its full path in the reader's output directory.
def get_published_file_path(filename):
   return os.path.join(reader_outputdir, filename)
 

# Retrieves the publication address, amount, and block listener port from a
# bitclamp process.  The --unittest-publication-address argument tells
# bitclamp.py where to save the publication address and amount on the
# filesystem; the path to that file is the argument to this function.
#
# Returns a tuple containing the publication address, amount, and block
# listener port on success (and deletes the file), or (None, None, None) on
# error.
def get_publication_info(publication_info_path):
  i = 0
  continue_flag = True
  while continue_flag:
    # If the file exists and is not empty, we are done waiting.
    if os.path.isfile(publication_info_path) and os.path.getsize(publication_info_path) > 0:
      continue_flag = False

    # Otherwise, wait up to 7 seconds.
    else:
      time.sleep(0.5)

      # If we've been waiting over 7 seconds, we failed.
      i += 1
      if i > 14:
        return None, None, None

  line = None
  with open(publication_info_path, 'r') as f:
    fcntl.lockf(f, fcntl.LOCK_SH)
    line = f.read()

  # Delete the file.
  os.remove(publication_info_path)

  # Return a tuple containing the publication address, amount, and block
  # listener port.
  fields = line.split(' ')
  return fields[0], fields[1], int(fields[2])


# Returns the *.state file for the terminated bitclamp process (used for
# restoring interrupted publications).
def get_state_file():
  writer_home_dir = os.path.expanduser('~%s' % user_writer)
  for f in os.listdir(writer_home_dir):
    if f.endswith('.state'):
      return os.path.join(writer_home_dir, f)

  print("FAILED TO FIND STATE FILE.")
  exit(-1)


# Initializes the Utils subsystem.
def init_utils(code_dir, chain):

  global chain_str, chain_btc, cli, writer_tempdir, writer_block_listener_file, bitclamp_py, bitclamp_extracterizer_py, user_writer, user_reader, change_address, reader_outputdir, reader_partialdir, reader_lockfile, btc_classic, sqlite3_file

  chain_str = chain.lower()
  chain_btc = True
  cli = 'bitcoin-cli'
  user_writer = 'btcwriter'
  user_reader = 'btcreader'
  if chain.upper() == 'DOGE':
    chain_btc = False
    cli = 'dogecoin-cli'
    user_writer = 'dogewriter'
    user_reader = 'dogereader'

  # Get the path to the writer's temp directory.
  writer_tempdir = os.path.join(os.path.expanduser('~%s' % user_writer), 'tmp/')

  # Get the path to the writer's block listener file.
  writer_block_listener_file = os.path.join(os.path.expanduser('~%s' % user_writer), 'block_listeners.txt')

  # Get the path to the reader's output directory.
  reader_outputdir = os.path.join(os.path.expanduser('~%s' % user_reader), 'output/')
  reader_partialdir = os.path.join(reader_outputdir, 'partial/')

  # Delete the log file in the reader's output directory, if it exists.
  log_file = os.path.join(reader_outputdir, 'log.txt')
  if os.path.isfile(log_file):
    os.remove(log_file)

  # Delete the lock file in the reader's output directory, if it exists.
  reader_lockfile = os.path.join(reader_outputdir, 'lockfile')
  if os.path.isfile(reader_lockfile):
    os.remove(reader_lockfile)

  # Delete the SQLite3 database, if it exists.
  sqlite3_file = os.path.join(reader_outputdir, 'bitclamp_sqlite.db')
  if os.path.isfile(sqlite3_file):
    os.remove(sqlite3_file)

  # Get the path to bitclamp.py.
  bitclamp_py = os.path.join(code_dir, 'bitclamp.py')
  if not os.path.isfile(bitclamp_py):
    print("%s does not exist!  Terminating." % bitclamp_py)
    exit(-1)

  # Get the path to bitclamp_extracterizer.py.
  bitclamp_extracterizer_py = os.path.join(code_dir, 'bitclamp_extracterizer.py')
  if not os.path.isfile(bitclamp_extracterizer_py):
    print("%s does not exist!  Terminating." % bitclamp_extracterizer_py)
    exit(-1)

  # Get the writer's account address to use as the change address.
  so, se = exec_wait(user_writer, '%s getaccountaddress \"\"' % cli)
  change_address = so.decode('ascii').strip()

  # If we are using BTC, determine if we are using Bitcoin Core or
  # Bitcoin Classic.
  if chain_btc:
    so, se = exec_wait(user_writer, '%s --version' % cli)
    if so.decode('ascii').find('Bitcoin Core') != -1:
      btc_classic = False


  # Ensure that the daemons are running.
  if chain_btc:
    exec_wait(user_writer, '/bin/bash -c ./btc_run_bitcoind_writer.sh')
    exec_wait(user_reader, '/bin/bash -c ./btc_run_bitcoind_reader.sh')
  else:
    exec_wait(user_writer, '/bin/bash -c ./doge_run_dogecoind_writer.sh')
    exec_wait(user_reader, '/bin/bash -c ./doge_run_dogecoind_reader.sh')


# Creates a file with the specified data in the writer's temp directory.
# Returns the full path and the file's SHA-512 hash.
def make_file(name, data):
  filepath = os.path.join(writer_tempdir, name)
  with open(filepath, 'wb') as f:
    f.write(data)
  return filepath, calc_sha512(filepath)


# Creates a file in the writer's temp directory and fills it with random data.
# Returns the full path and the file's SHA-512 hash.
def make_rand_file(name, size):
  temp_file = os.path.join(writer_tempdir, name)
  exec_wait(user_writer, 'dd if=/dev/urandom of=%s bs=%d count=1' % (temp_file, size))
  return temp_file, calc_sha512(temp_file)


# Creates a temporary file in the system temp directory that the writer user
# can use.  clean_temp_files() will automatically delete this file if it still
# exists later.
def make_temp_file():
   temp_file, ignored = exec_wait(user_writer, 'mktemp')
   temp_file = temp_file.decode('ascii').strip()
   temp_files.append(temp_file)
   return temp_file


# Creates a temporary directory for the reader.  Note that this will NOT be
# automatically removed by any process; the caller must remove it manually.
def make_reader_temp_dir():
  so, se = exec_wait_reader('mktemp -d')
  return so.decode('ascii').strip()


# Creates a temp file in the writer's directory.
def make_writer_temp_file():
  temp_file, ignored = exec_wait(user_writer, 'mktemp -p %s' % writer_tempdir)
  return temp_file.decode('ascii').strip()


# Prints a file's contents to stdout.
def print_output_file(bitclamp_stdout_file):
  with open(bitclamp_stdout_file, 'r') as f:
    print(f.read())


# Runs bitclamp with the specified arguments.
#
#   expected_output_file: the output filename expected upon successful
#                         publication.
#   expected_output_file_size: the output file size expected.
#   num_outputs:          the number of outputs to send per transaction.
#   num_transactions:     the number of parallel transactions to transmit per
#                         block.
#
# Returns a tuple containing a boolean denoting success or failure, the process
# handle, a file handle to bitclamp's stdout & stderr stream, and the output
# file created (useful for when publications with no filename are made).
def run_bitclamp(args, expected_output_file, expected_output_file_size = 0, num_outputs = 5, num_transactions = 1):
  ret = True

  is_restore_operation = (args.find('--restore=') != -1)

  bitclamp_stdout_file = make_temp_file()
  publication_info_path = make_temp_file()

  # If the defaults are used, don't include --noutputs and -ntransactions.
  # This mimics how the user invokes the program, which can better test for
  # potential bugs.
  pub_ctrl = ''
  if (num_outputs != 5) or (num_transactions != 1):
    pub_ctrl = '--noutputs=%d --ntransactions=%d' % (num_outputs, num_transactions)

  # If this isn't a publication restoration, add some default arguments.
  if not is_restore_operation:
    args = '--regtest %s %s --change=%s --unittest-publication-address=%s' % (args, pub_ctrl, change_address, publication_info_path)
    if chain_btc:
      args = '%s --chain=btc --txfee=0.0003' % args
    else:
      args = '%s --chain=doge --txfee=1' % args
  else:
    args = '%s --unittest-publication-address=%s' % (args, publication_info_path)

  args = '%s --debug --daemon=existing' % args

  # Run bitclamp in the background and return immediately.
  proc, output_fd = exec_async(user_writer, 'python3 %s %s' % (bitclamp_py, args), bitclamp_stdout_file)
  output_fd.close()

  publish_address, amount, block_listener_port = get_publication_info(publication_info_path)
  if publish_address is None:
    print('Failed to get publication address & amount. %s, %r, %d, [%s]' % (publication_info_path, os.path.isfile(publication_info_path), os.path.getsize(publication_info_path), args))
    print_output_file(bitclamp_stdout_file)
    return False, proc, bitclamp_stdout_file, ''

  # If the block listener file doesn't exist, create it under the context of
  # the writer user.
  if not os.path.isfile(writer_block_listener_file):
    exec_wait(user_writer, '/bin/bash -c "touch %s"' % writer_block_listener_file)

  # Write the port of the BlockListener to the file so that the writer's
  # BlockClient can connect to it.
  with open(writer_block_listener_file, 'w+') as f:
    fcntl.lockf(f, fcntl.LOCK_EX)
    f.write("localhost %d 0 0\n" % block_listener_port)

  # If we aren't restoring an interrupted publication, send the required
  # funds to the publication address.
  if not is_restore_operation:

    # Round up the amount if we're using dogecoin.
    if not chain_btc:
      # Convert the string to float, round up, cut off the decimals, then
      # convert back to a string.
      amount = str(int(math.ceil(float(amount))))

    # Send the funds to the publication address to start the process.
    send_funds(publish_address, amount)

  # If the expected_output_file is None (i.e.: when we are testing publications
  # with no filenames), look in the output and partial directories for a file
  # that begins with 'unnamed_file_'.  That is the prefix for files that were
  # published with a blank filename.
  if expected_output_file is None:

    # The partial directory may be empty at this point, so generate blocks
    # until its not (and while bitclamp is still running).
    while (proc.poll() is None) and expected_output_file is None:

      # Ensure that the reader processed all the blocks that the writer has
      # written. 
      wait_for_reader_writer_sync()

      # Look through the reader's partial directory for a file that begins with
      # "unnamed_file_"
      for f in os.listdir(reader_partialdir):
        if f.startswith('unnamed_file_') and not f.endswith('.state'):
          expected_output_file = os.path.join(reader_outputdir, f)
          break

      # If we didn't find the file, generate a block and loop.  Otherwise,
      # we're done.
      if expected_output_file is None:
        generate_blocks(1, True)
      else:
        break

  # While bitclamp is still running, and while the output file doesn't exist
  # (or isn't large enough), keep generating blocks.
  while (proc.poll() is None) and ((os.path.isfile(expected_output_file) is False) or (os.path.getsize(expected_output_file) < expected_output_file_size)):
    generate_blocks(1, True)

  # Wait for the reader to fully sync up with the writer, to ensure that the
  # reader has re-assembled the file properly on its end.
  wait_for_reader_writer_sync()

  # Return True if the expected output file exists, and it is at least the
  # expected size.
  ret = os.path.isfile(expected_output_file) and (os.path.getsize(expected_output_file) >= expected_output_file_size)

  if ret is False:
    print('run_bitclamp() is returning False')
    if not os.path.isfile(expected_output_file):
      print('%s is not a file.' % expected_output_file)
      print('reader output dir: %s' % ', '.join(os.listdir(reader_outputdir)))
      print('reader partial dir: %s' % ', '.join(os.listdir(reader_partialdir)))
    else:
      print('%s exists, and is %d bytes.  Expected size: %d.' % (expected_output_file, os.path.getsize(expected_output_file), expected_output_file_size))

  return ret, proc, bitclamp_stdout_file, expected_output_file


# Runs bitclamp_extracterizer.py.
def run_bitclamp_extracterizer(temp_dir, args = ''):
  exec_wait_reader('python3 %s --regtest --chain=%s --output=%s %s' % (bitclamp_extracterizer_py, chain_str, temp_dir, args))


# As the writer user, sends the specified amount to the specified address.
def send_funds(address, amount):
  exec_wait(user_writer, '%s sendtoaddress %s %s' % (cli, address, amount))
  generate_blocks(1, True)


# Ensure that the bitclamp process is killed and the output file is deleted.
def stop_bitclamp(proc, output_file):

  # Truncate the block listener file.
  with open(writer_block_listener_file, 'w') as f:
    fcntl.lockf(f, fcntl.LOCK_EX)

  # If poll() is None, the process is still running, so kill it.
  if proc.poll() is None:
    from time import sleep
    proc.terminate()

    sleep(0.25)
    while proc.poll() is None:
      proc.terminate()
      sleep(0.25)

  # Ensure that the process is no longer running.
  if proc.poll() is None:
    print('Failed to terminate bitclamp process!')

  if os.path.isfile(output_file):
    os.remove(output_file)


# Waits for the reader and writer to synchronize on the number of blocks they
# each have.
def wait_for_reader_writer_sync():

  # Wait up to 60 seconds for the reader's lock file to be created.
  timeout = 0
  while (not os.path.isfile(reader_lockfile)) or (os.path.getsize(reader_lockfile) == 0):
    time.sleep(1)
    timeout += 1

    if timeout > 60:
      print('Timeout while waiting for reader\'s lock file.  Terminating.')
      exit(-1)

  # Get the number of blocks from the writer.
  writer_block_count = -1
  try:
    so, se = exec_wait(user_writer, '/bin/bash -c "%s getblockcount"' % cli)
    writer_block_count = int(so)
  except Exception as e:
    print('Failed to parse writer block count: %s' % str(e))
    exit(-1)

  # Loop until the reader's last processed block matches the writer's total
  # block count.
  reader_last_block_processed = -2
  while reader_last_block_processed != writer_block_count:

    block_info = None
    while block_info is None:
      try:
        # Open the reader's lock file.  The latest block it parsed is stored
        # inside.
        with open(reader_lockfile, 'rb') as f:
          fcntl.lockf(f, fcntl.LOCK_SH)
          block_info = pickle.loads(f.read())
      except Exception as e:
        print('Error while reading reader\'s lock file: %s' % str(e))
        exit(-1)

      reader_last_block_processed = block_info['last_block_num_processed']
      if reader_last_block_processed != writer_block_count:
        time.sleep(0.2)
