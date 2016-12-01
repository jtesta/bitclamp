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

import hashlib, math, os, subprocess, time

# A list of temporary files created by make_temp_file().
temp_files = []

# The full patch to the bitclamp.py script.
bitclamp_py = None

# The temp directory inside the writer's home directory.
writer_tempdir = None

# The output directory inside the reader's home directory.
reader_outputdir = None

# The address to send all change to.
change_address = None

# True if we are using the BTC chain, otherwise we are using DOGE.
chain_btc = None

# If true, Bitcoin Classic is in use, otherwise Bitcoin Core.
btc_classic = True

# The cli program to use.  'bitcoin-cli' for BTC, and 'dogecoin-cli' for DOGE.
cli = None

# The usernames of the writer and reader users, respectively.
user_writer = None
user_reader = None


# Removes any leftover files from a previous publication in the output
# directory, and returns two new temporary files.
def begin_test():
  # Delete all files in the output directory that isn't the log file.
  for f in os.listdir(reader_outputdir):
    full_path = os.path.join(reader_outputdir, f)
    if os.path.isfile(full_path) and f != 'log.txt' and f != 'lockfile':
      os.remove(full_path)

  # Delete all files in the partial/ sub-directory.
  for f in os.listdir(os.path.join(reader_outputdir, 'partial/')):
    os.remove(os.path.join(reader_outputdir, 'partial/', f))

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


# Generates 'num_blocks', and waits 'gen_wait' seconds afterwards.
def generate_blocks(num_blocks, gen_wait):
  exec_wait(user_writer, '/bin/bash -c "%s generate %d \$PUBKEY; sleep %.1f"' % (cli, num_blocks, gen_wait))


# Given a filename, returns its full path in the reader's partial output
# directory.
def get_partial_file_path(filename):
  return os.path.join(reader_outputdir, 'partial/', filename)


# Given a filename, returns its full path in the reader's output directory.
def get_published_file_path(filename):
   return os.path.join(reader_outputdir, filename)
 

# Retrieves the publication address and amount from a bitclamp process.  The
# --unittest-publication-address argument tells bitclamp.py where to save the
# publication address and amount on the filesystem; the path to that file is
# the argument to this function.
#
# Returns a tuple containing the publication address and amount on success (and
# deletes the file), or (None, None) on error.
def get_publication_address(address_path, output_file):
  i = 0
  continueFlag = True
  while continueFlag is True:
    # If the file exists and is not empty, we are done waiting.
    if os.path.isfile(address_path) and os.path.getsize(address_path) > 0:
      continueFlag = False

    # Otherwise, wait up to 7 seconds.
    else:
      time.sleep(0.5)

      # If we've been waiting over 7 seconds, we failed.
      i += 1
      if i > 14:
        # Print out the output file; perhaps there's useful debugging info
        # there.
        print("Failed to get the publication address & amount!")
        with open(output_file, 'r') as f:
          print(f.read())
        return None, None

  line = None
  with open(address_path, 'r') as f:
    line = f.read()

  # Delete the file.
  os.remove(address_path)

  # Return a tuple containing the publication address and amount.
  fields = line.split(' ')
  return fields[0], fields[1]


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

  global chain_btc, cli, writer_tempdir, bitclamp_py, user_writer, user_reader, change_address, reader_outputdir, btc_classic

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

  # Get the path to the reader's output directory.
  reader_outputdir = os.path.join(os.path.expanduser('~%s' % user_reader), 'output/')

  # Delete the log file in the reader's output directory, if it exists.
  log_file = os.path.join(reader_outputdir, 'log.txt')
  if os.path.isfile(log_file):
    os.remove(log_file)

  # Delete the lock file in the reader's output directory, if it exists.
  lock_file = os.path.join(reader_outputdir, 'lockfile')
  if os.path.isfile(lock_file):
    os.remove(lock_file)

  # Get the path to bitclamp.py.
  bitclamp_py = os.path.join(code_dir, 'bitclamp.py')
  if not os.path.isfile(bitclamp_py):
    print("%s does not exist!  Terminating." % bitclamp_py)
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
#   gen_wait:             the number of seconds to wait in between generating
#                         blocks.
#   num_outputs:          the number of outputs to send per transaction.
#   num_transactions:     the number of parallel transactions to transmit per
#                         block.
#
# Returns a tuple containing a boolean denoting success or failure, the process
# handle, and a file handle to bitclamp's stdout & stderr stream.
def run_bitclamp(args, expected_output_file, expected_output_file_size = 0, gen_wait = 1.2, num_outputs = 5, num_transactions = 1):
  ret = True

  is_restore_operation = (args.find('--restore=') != -1)

  bitclamp_stdout_file = make_temp_file()
  address_path = make_temp_file()

  # If the defaults are used, don't include --noutputs and -ntransactions.
  # This mimics how the user invokes the program, which can better test for
  # potential bugs.
  pub_ctrl = ''
  if (num_outputs != 5) or (num_transactions != 1):
    pub_ctrl = '--noutputs=%d --ntransactions=%d' % (num_outputs, num_transactions)

  # If this isn't a publication restoration, add some default arguments.
  if not is_restore_operation:
    args = '--regtest %s %s --change=%s --unittest-publication-address=%s' % (args, pub_ctrl, change_address, address_path)
    if chain_btc:
      args = '%s --chain=btc --txfee=0.0003' % args
    else:
      args = '%s --chain=doge --txfee=1' % args

  # Run bitclamp in the background and return immediately.
  proc, output_fd = exec_async(user_writer, 'python3 %s %s' % (bitclamp_py, args), bitclamp_stdout_file)
  output_fd.close()

  # If this is not a restoration operation, get the publication address and
  # send funds to it.
  if not is_restore_operation:
    publish_address, amount = get_publication_address(address_path, bitclamp_stdout_file)
    if publish_address is None:
      print("FAILED TO GET PUBLICATION ADDRESS & AMOUNT!")
      return False, proc, bitclamp_stdout_file

    # Round up the amount if we're using dogecoin.
    if not chain_btc:
      # Convert the string to float, round up, cut off the decimals, then
      # convert back to a string.
      amount = str(int(math.ceil(float(amount))))

    # Send the funds to the publication address to start the process.
    send_funds(publish_address, amount)

  # While bitclamp is still running, and while the output file doesn't exist
  # (or isn't large enough), keep generating blocks.
  while (proc.poll() is None) and ((os.path.isfile(expected_output_file) is False) or (os.path.getsize(expected_output_file) < expected_output_file_size)):
    generate_blocks(1, gen_wait)

  # Return True if the expected output file exists, and it is at least the
  # expected size.
  ret = os.path.isfile(expected_output_file) and (os.path.getsize(expected_output_file) >= expected_output_file_size)

  return ret, proc, bitclamp_stdout_file
  

# As the writer user, sends the specified amount to the specified address.
def send_funds(address, amount):
  exec_wait(user_writer, '%s sendtoaddress %s %s' % (cli, address, amount))


# Ensure that the bitclamp process is killed and the output file is deleted.
def stop_bitclamp(proc, output_file):

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
    print("FAILED TO TERMINATE BITCLAMP PROCESS!")

  if os.path.isfile(output_file):
    os.remove(output_file)
