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


# This program runs unit tests.  Invoked from the top-level Makefile via
# "make alltests" or "make coretests".

import atexit, os, shutil, sys, time
from UnitTestUtils import *


# Upon program exit, deletes all temporary files created by make_temp_file().
def exit_handler():
  clean_temp_files()


# Creates a file filled with random bytes of a specified size.  Publishes that
# file with 'num_outputs' outputs and 'num_transactions' parallel transactions.
# 'gen_wait' is the number of seconds to wait in between blocks.
def rand_file_test(size, num_outputs = 5, num_transactions = 1, gen_wait = 1.2, additional_args = ''):
  rand_filename = 'rand_%d_%dOut_%dTX.bin' % (size, num_outputs, num_transactions)
  rand_bin, rand_bin_hash = make_rand_file(rand_filename, size)

  filepath_complete = get_published_file_path(rand_filename)
  return general_file_test(rand_bin, rand_bin_hash, filepath_complete, num_outputs, num_transactions, gen_wait, additional_args)


def general_file_test(filepath_source, filepath_source_hash, filepath_complete, num_outputs = 5, num_transactions = 1, gen_wait = 1.2, additional_args = ''):
  output_file, address_path = begin_test()

  # If the defaults are used, don't include --noutputs and -ntransactions.
  # This mimics how the user invokes the program, which can better test for
  # potential bugs.
  pub_ctrl = ''
  if (num_outputs != 5) or (num_transactions != 1):
    pub_ctrl = '--noutputs=%d --ntransactions=%d' % (num_outputs, num_transactions)

  ret, proc, bitclamp_stdout_file, filepath_complete = run_bitclamp('--file=%s --content-type=undefined %s --unittest-publication-address=%s %s' % (filepath_source, pub_ctrl, address_path, additional_args), expected_output_file=filepath_complete)
  if ret is False:
    print_output_file(bitclamp_stdout_file)

  # Ensure that the output file's hash matches the original file's.
  elif does_output_file_match(filepath_complete, filepath_source_hash) is False:
    print('ERROR: original file hash does not match published file hash!')
    ret = False

  # Delete the random file and ensure bitclamp is stopped.
  if os.path.isfile(filepath_source):
    os.remove(filepath_source)

  if os.path.isfile(filepath_complete):
    os.remove(filepath_complete)

  stop_bitclamp(proc, bitclamp_stdout_file)
  return ret


# Tests the deadman switch functionality.  Publishes a deadman switch file, then
# its key.  Ensures that the file is unreadable until the key is given.
def deadman_switch_test(data, num_outputs = 5, num_transactions = 1, gen_wait = 1.2):
  unused, unused2 = begin_test()

  # Create a random filename in the writer's temp directory.  Delete the empty
  # file that's created since the main program won't overwrite existing files.
  deadman_switch_key =  make_writer_temp_file()
  os.remove(deadman_switch_key)

  # Create a file named secrets.txt.
  filename = 'deadman_switch_%d_%dOut_%dTX.txt' % (len(data), num_outputs, num_transactions)

  # Get the path where it will land as a partial file, and where it will land
  # after fully published with the key.
  filepath_partial = get_partial_file_path(filename)
  filepath_complete = get_published_file_path(filename)

  # Write the data to disk and get its full path and SHA512 hash.
  secrets_txt, secrets_txt_hash = make_file(filename, data)

  # Publish the file without the key.
  ret, proc, bitclamp_stdout_file, unused = run_bitclamp('--file=%s --deadman-switch-save=%s --compression=none' % (secrets_txt, deadman_switch_key), expected_output_file=filepath_partial, expected_output_file_size=len(data))

  # Check if the partial file is GPG-encrypted.
  if ret is False:
    print_output_file(bitclamp_stdout_file)
  else:
    so, se = exec_wait_reader('file %s' % filepath_partial)
    so = so.decode('ascii').strip()
    if not so.endswith(': GPG symmetrically encrypted data (AES256 cipher)'):
      print('ERROR: deadman switch file is not encrypted with GPG!: %s' % so)
      ret = False

  if ret is False:
    print_output_file(bitclamp_stdout_file)
  else:
    stop_bitclamp(proc, bitclamp_stdout_file)

    # Now publish the key.
    ret, proc, bitclamp_stdout_file, unused = run_bitclamp('--deadman-switch-publish=%s' % deadman_switch_key, expected_output_file=filepath_complete, expected_output_file_size=len(data))
    if ret is False:
      print_output_file(bitclamp_stdout_file)

    # Ensure that the original file's hash matches what was published.
    elif does_output_file_match(filename, secrets_txt_hash) is False:
      print('ERROR: deadman switch not successfully decrypted!')
      ret = False

  if os.path.isfile(deadman_switch_key):
    os.remove(deadman_switch_key)

  if os.path.isfile(secrets_txt):
    os.remove(secrets_txt)

  if os.path.isfile(filepath_partial):
    os.remove(filepath_partial)

  if os.path.isfile(filepath_complete):
    os.remove(filepath_complete)

  stop_bitclamp(proc, bitclamp_stdout_file)
  return ret


# Begins publishing a file, then interrupts it and resumes it.
def restore_test(size = -1, num_outputs = 5, num_transactions = 1, gen_wait = 1.2):
  from os import urandom
  from random import randrange

  output_file, address_path = begin_test()

  # If no size was specified, choose a random size from 8K to 12K.
  if size == -1:
    size = (int.from_bytes(urandom(2), byteorder='little') % 4096) + 8192

  # Interrupt the publication randomly after 25 - 50% of it is completed.
  interrupt_size = int((size * randrange(25, 50)) / 100)

  rand_filename = 'rand_restore_%d_%dOut_%dTX.bin' % (size, num_outputs, num_transactions)
  rand_bin, rand_bin_hash = make_rand_file(rand_filename, size)

  filepath_partial = get_partial_file_path(rand_filename)
  filepath_complete = get_published_file_path(rand_filename)

  # If the defaults are used, don't include --noutputs and -ntransactions.
  # This mimics how the user invokes the program, which can better test for
  # potential bugs.
  pub_ctrl = ''
  if (num_outputs != 5) or (num_transactions != 1):
    pub_ctrl = '--noutputs=%d --ntransactions=%d' % (num_outputs, num_transactions)

  # Begin publication, but stop before fully finishing.
  ret, proc, bitclamp_stdout_file, unused = run_bitclamp('--debug --file=%s --content-type=undefined %s --unittest-publication-address=%s' % (rand_bin, pub_ctrl, address_path), expected_output_file=filepath_partial, expected_output_file_size=interrupt_size)


  if ret is False:
    print_output_file(bitclamp_stdout_file)
    stop_bitclamp(proc, bitclamp_stdout_file)
    if os.path.isfile(filepath_partial):
      os.remove(filepath_partial)
    return False

  # Kill the bitclamp process.  This writes out the state file to disk.
  stop_bitclamp(proc, bitclamp_stdout_file)

  # Generate 100 blocks.
  generate_blocks(100, 0)

  # Restore publication using the state file.
  ret, proc, bitclamp_stdout_file, unused = run_bitclamp('--debug --restore=%s' % (get_state_file()), expected_output_file=filepath_complete, expected_output_file_size=size)

  if ret is False:
    print_output_file(bitclamp_stdout_file)
  elif does_output_file_match(filepath_complete, rand_bin_hash) is False:
    print('ERROR: original file hash does not match published file hash!')
    ret = False

  # Delete the random file and ensure bitclamp is stopped.
  if os.path.isfile(filepath_complete):
    os.remove(filepath_complete)

  if os.path.isfile(rand_bin):
    os.remove(rand_bin)

  stop_bitclamp(proc, bitclamp_stdout_file)
  return ret


# Publishes a short 3-byte file.
def Core_Short():
  return rand_file_test(3)


# Publishes a random 4KB file.
def Core_Rand_4KB():
  return rand_file_test(4*1024)


# Publishes a random 24KB file.
def Core_Rand_24KB():
  return rand_file_test(24*1024)


# Publishes a random, variable-sized file from 1 to 16KB.
def Core_Rand_Variable():
  from os import urandom

  # Generate a random number between 1 and 16K:
  random_len = (int.from_bytes(urandom(2), byteorder='little') % 16383) + 1
  ret = rand_file_test(random_len)
  if ret is False:
    print("(%d) " % random_len, end="")

  return ret


# Publishes a plaintext, repeating file between 2KB and 6KB.
def Core_Plaintext_Repeating_NoCompression_Variable():
  from os import urandom
  random_len = (int.from_bytes(urandom(2), byteorder='little') % 4096) + 2048

  filename = 'plaintext_%d.txt' % random_len
  filepath_source, filepath_source_hash = make_file(filename, b'\x65' * random_len)
  filepath_complete = get_published_file_path(filename)

  return general_file_test(filepath_source, filepath_source_hash, filepath_complete, additional_args='--no-crypto --compression=none')


# Publishes a random 64KB file with 10 outputs and 3 transactions per block.
def Core_Rand_64KB_10Out_3TX():
  return rand_file_test(64*1024, 10, 3)


# Publishes an 8KB deadman switch, and then its key.
def Core_Deadman_Switch_Test():
  data = (b'\x41' * (4 * 1024)) + (b'\x5a' * (4 * 1024))
  return deadman_switch_test(data)


# Begins to publish a random 8K - 12K file, interrupts it, then resumes.
def Core_Restore_Test():
  return restore_test()


# Checks that a custom filename can be set.
def Aux_Custom_Filename():
  filepath_source, filepath_source_hash = make_rand_file('custom_filename1.txt', 999)
  filepath_complete = get_published_file_path('supercool.exe')

  return general_file_test(filepath_source, filepath_source_hash, filepath_complete, additional_args='--name="supercool.exe"')


# Ensures that a filename with a relative path will not result in writing
# outside the output directory.
def Aux_Malicious_Filename():
  filepath_source, filepath_source_hash = make_rand_file('custom_filename2.txt', 999)
  filepath_complete = get_published_file_path('malicious_filename.exe')

  return general_file_test(filepath_source, filepath_source_hash, filepath_complete, additional_args='--name="../malicious_filename.exe"')


# Check that blank filenames are properly published.
def Aux_No_Filename():
  filepath_source, filepath_source_hash = make_rand_file('custom_filename3.txt', 999)

  return general_file_test(filepath_source, filepath_source_hash, None, additional_args='--name=""')


# Checks that a custom description can be set.
def Aux_Custom_Description():
  filename = 'custom_description.txt'
  description = "SUPERCALIFRAGILISTICEXPIALIDOCIOUS"
  filepath_source, filepath_source_hash = make_rand_file(filename, 999)
  filepath_complete = get_published_file_path(filename)

  ret = general_file_test(filepath_source, filepath_source_hash, filepath_complete, additional_args='--description="%s"' % description)
  if not ret:
    return False

  extracted_description = database_get_file_description(filename)
  if extracted_description != description:
    return False
  else:
    return True


# 1MB random file with 20 outputs and 10 transactions.
def Aux_Rand_1MB_20Out_10TX():
  return rand_file_test(1024*1024, num_outputs=20, num_transactions=10, gen_wait=2.1)


# 100KB random file.  Takes almost 2 minutes to complete.
def Aux_Rand_100KB():
  return rand_file_test(100*1024, gen_wait=1.7)


# 512KB random file.  Takes over 7 minutes to complete.
def Aux_Rand_512KB():
  return rand_file_test(512*1024, gen_wait=1.7)


# Use bitclamp_extracterizer.py to extract content.
def Aux_Extract_All_Content():
  ret = False
  so, se = exec_wait_reader('mktemp -d')
  temp_dir = so.decode('ascii').strip()

  # Extract all files into a temporary directory.  Only files published since
  # the last invokation of unit tests will be extracted.
  run_bitclamp_extracterizer(temp_dir, '--start-block=%d' % database_get_first_block_num())

  # Get a list of all published filenames.
  filenames = database_get_file_list()

  # Traverse the output directory.  Remove each file found from the list of
  # published filenames.  What's left should be an empty list, otherwise any
  # filenames remaining were those that were not successfully extracted.
  for f in os.listdir(temp_dir):
    if f in filenames:
      filenames.remove(f)

    # Files that begin with 'unnamed_file_' were published with no filename,
    # so remove '' from the list.
    elif f.startswith('unnamed_file_'):
      filenames.remove('')

  # If all filenames were removed from the list.
  if len(filenames) == 0:
    ret = True

    # Remove the temporary directory.
    shutil.rmtree(temp_dir)
  else:
    # Print error messages.  Don't delete the temporary directory so that the
    # user can manually inspect it.
    print()
    print('FAILED TO EXTRACT (%d): [%s]' % (len(filenames), ','.join(filenames)))
    print('Temporary directory: %s' % temp_dir)
    print()

  return ret


if __name__ == "__main__":
  atexit.register(exit_handler)

  code_dir = sys.argv[1]
  run_all_tests = (sys.argv[2] == 'all')

  tests = []
  tests.append(Core_Short)
  tests.append(Core_Rand_4KB)
  tests.append(Core_Rand_Variable)
  tests.append(Core_Rand_24KB)
  tests.append(Core_Rand_64KB_10Out_3TX)
  tests.append(Core_Restore_Test)
  tests.append(Core_Deadman_Switch_Test)
  tests.append(Core_Plaintext_Repeating_NoCompression_Variable)

  if run_all_tests:
    tests.append(Aux_Custom_Filename)
    tests.append(Aux_Malicious_Filename)
    tests.append(Aux_No_Filename)
    tests.append(Aux_Custom_Description)
    tests.append(Aux_Rand_1MB_20Out_10TX)
    tests.append(Aux_Rand_100KB)
    tests.append(Aux_Rand_512KB)
    tests.append(Aux_Extract_All_Content)

  print()
  if run_all_tests:
    print("Running ALL tests...")
  else:
    print("Running CORE tests ONLY...")
  print()

  for network in ['BTC', 'DOGE']:
    init_utils(code_dir, network)

    print("Running %s tests..." % network)
    print()

    num_failed = 0
    for test in tests:
      print("\tRunning %s..." % test.__name__, end=" ")
      sys.stdout.flush()
      if not test():
        print("FAILED!!")
        num_failed += 1
      else:
        print("passed.")

    if num_failed > 0:
      print("\n%d %s TESTS FAILED!!\n" % (num_failed, network))
      exit(-1)
    else:
      print("\nALL %d %s TESTS PASSED!!\n" % (len(tests), network))

  exit(0)
