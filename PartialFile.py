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


# This class represents a partial file in the blockchain.

import binascii, fcntl, hashlib, mmap, os, pickle

class PartialFile:
   def __init__(self, debug_func, initial_txid, output_dir, partial_dir, sanitized_filename, description, file_size, general_flags, encryption_type, content_type, compression_type, file_hash, initial_block_num):
      self.debug_func = debug_func
      self.initial_txid = initial_txid
      self.output_dir = output_dir
      self.sanitized_filename = sanitized_filename
      self.description = description
      self.file_size = file_size
      self.general_flags = general_flags
      self.encryption_type = encryption_type
      self.content_type = content_type
      self.compression_type = compression_type
      self.file_hash = file_hash

      # The block number that this was initially found in.
      self.initial_block_num = initial_block_num

      # The block number of the last write operation.
      self.final_block_num = -1

      self.file_path = PartialFile.get_unique_filepath(initial_txid, partial_dir, sanitized_filename)
      self.state_file = self.file_path + '.state'

      self.file_ptr = 0
      self.block_acks = {}
      self.previous_txids = [self.initial_txid]
      self.temporal_key = None
      self.num_parallel_txs = -1
      self.finalized = False


   # Logs a debugging message.
   def d(self, s):
      self.debug_func(s)


   # Returns a list of TXIDs that previously held data for this file.
   def get_previous_txids(self):
      return self.previous_txids


   # Adds a TXID that held data for this file.
   def add_previous_txid(self, previous_txid):
      if previous_txid not in self.previous_txids:
         self.previous_txids.append(previous_txid)


   # Serialize this PartialFile to disk.
   def save_state(self):
      self.d('Dumping PartialFile object to %s' % self.state_file)
      with open(self.state_file, 'wb') as f:
         pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)


   # Write data from the blockchain into the local file.
   def write_data(self, data, offset):
      if offset > self.file_size:
         raise Exception("Offset (%d) is larger than file size (%d)!" % (offset, self.file_size))
      elif offset < 0:
         raise Exception("Offset is negative!: %d" % offset)
      elif len(data) == 0:
         raise Exception("Data length is 0!")


      if offset + len(data) > self.file_size:
         truncated_len = self.file_size - offset

         self.d("Offset (%d) + data length (%d) is greater than file size (%d). Truncated data to %d" % (offset, len(data), self.file_size, truncated_len))

         data = data[0:truncated_len]


      with open(self.file_path, 'a+b') as f:
         fcntl.lockf(f, fcntl.LOCK_EX)

         data_len = len(data)

         f.seek(0, os.SEEK_END)
         size = f.tell()
         if offset + data_len > size:
            change = (offset + data_len - size)
            self.d("Enlarging the file by %d bytes." % change)
            f.write(b'\xff' * change)
            f.flush()

         mm = mmap.mmap(f.fileno(), 0)
         mm[offset:offset + data_len] = data
         mm.close()

      # Maintain a sliding window of data received, much like TCP's sliding
      # window algorithm.  Because blocks can be written out of order, we
      # must maintain a pointer that tracks up to where contiguous data was
      # processed.  Past this, and sparse blocks are written.  The sparse blocks
      # (offsets and lengths) are maintained in the self.block_acks list.
      #
      # Once a block is written above, we will check if the number of contiguous
      # bytes can be updated and the pointer advanced.
      self.block_acks[offset] = len(data)
      for sorted_offset in sorted(self.block_acks):
         # If the pointer is equal to where an offset was just written, then
         # we found a contiguous block.  We can advance the pointer, then throw
         # out the record for the offset.
         if self.file_ptr == sorted_offset:
            self.file_ptr += self.block_acks[sorted_offset]
            del(self.block_acks[sorted_offset])

         # If we are beyond where an offset was written, this means we wrote
         # padding into the file, which will be over-written later.  We will
         # back up the pointer, then add in the offset's length.
         elif self.file_ptr > sorted_offset:
            self.file_ptr = sorted_offset + self.block_acks[sorted_offset]
            del(self.block_acks[sorted_offset])


   # Returns True if this is a deadman switch file, otherwise False.
   def is_deadman_switch_file(self):
      from Publication import Publication

      return True if (self.general_flags & Publication.GENERAL_FLAG_DEADMAN_SWITCH_FILE) == Publication.GENERAL_FLAG_DEADMAN_SWITCH_FILE else False


   # Returns True if this is a deadman switch key, otherwise False.
   def is_deadman_switch_key(self):
      from Publication import Publication

      return True if (self.general_flags & Publication.GENERAL_FLAG_DEADMAN_SWITCH_KEY) == Publication.GENERAL_FLAG_DEADMAN_SWITCH_KEY else False


   # Returns True if this file is completely published (and publicly readable), or False.  Note that fully published deadman switch files will return False here (is_complete_deadman_switch_file(), below, will return True, however).
   def is_complete(self):
      return True if (self.file_ptr == self.file_size) and (not self.is_deadman_switch_file()) else False


   # Returns True if this file is completely published, except for the deadman switch key.
   def is_complete_deadman_switch_file(self):
      return True if self.is_deadman_switch_file() and (self.file_ptr == self.file_size) else False


   # Returns True if this file is being published in plaintext.
   def is_plaintext_file(self):
      from Publication import Publication
      return self.encryption_type == Publication.ENCRYPTION_TYPE_NONE


   # Finalizes a fully published file.  Decrypts it if necessary, and moves it
   # to its output directory.  Deadman switch files are checked for correctness
   # (i.e.: that the published and extracted file hashes match), but are left
   # in the partial directory.
   #
   # Returns True on success, or False on error.
   def finalize(self, temporal_key, block_num):
      from Publication import Publication
      from Utils import Utils

      # If not all bytes were received, this is a failure.
      if (not self.is_complete()) and (not self.is_complete_deadman_switch_file()):
         self.d("Cannot finalize because file is not complete!")
         return False

      # Update the temporal key, if there is one.
      if (self.encryption_type != Publication.ENCRYPTION_TYPE_NONE) and \
         (temporal_key != (b'\x00' * 32)):
         self.temporal_key = temporal_key

      # Read the file we extracted.
      file_bytes = None
      with open(self.file_path, 'rb') as f:
         file_bytes = f.read()

      # Calculate the hash of the file we extracted.
      calculated_hash = hashlib.sha256(file_bytes).digest()

      # Check that the hash in the publication header matches what we have.
      if self.file_hash != calculated_hash:
         self.d("Hashes do not match!:\n%s\n%s" % (binascii.hexlify(self.file_hash).decode('ascii'), binascii.hexlify(calculated_hash).decode('ascii')))
         return False

      # If this file is a deadman switch, don't try to decrypt, since we don't
      # have the real key here.
      if self.is_deadman_switch_file() and (temporal_key == (b'\xff' * 32)):
         # Save the num_parallel_txs and encryption_type so that when the key
         # is found in the future, we know how to decrypt this.
         self.final_block_num = block_num
         self.save_state()
         return True

      # Get a unique filename in the output directory.
      new_file_path = PartialFile.get_unique_filepath(self.initial_txid, self.output_dir, self.sanitized_filename)

      # Decrypt the file, if necessary.
      if self.encryption_type == Publication.ENCRYPTION_TYPE_GPG2_AES256_SHA512:
         self.d("File is encrypted with type %s.  Decrypting..." % Publication.get_encryption_str(self.encryption_type))
         file_bytes = Utils.decrypt(file_bytes, self.temporal_key)
         if len(file_bytes) == 0:
            self.d("Decryption of file yielded zero bytes!")
            return False

         # Write the plaintext bytes into the output directory.
         with open(new_file_path, 'wb') as f:
            f.write(file_bytes)

         # Remove the encrypted file.
         os.unlink(self.file_path)

      else:
         # Move file out of partial directory into output directory.
         os.rename(self.file_path, new_file_path)

      # Delete the state file.
      os.unlink(self.state_file)

      # Update the final block number.
      self.final_block_num = block_num

      # Mark as finalized and return success.
      self.finalized = True
      return True


   # Return a string representation of this PartialFile.
   def __str__(self):
      import base64
      from Publication import Publication

      general_flags_str = 'General flags: '
      if self.is_deadman_switch_file():
         general_flags_str += 'Deadman Switch File'
      elif self.is_deadman_switch_key():
         general_flags_str += 'Deadman Switch Key'
      else:
         general_flags_str += 'None'

      s = ''
      if self.temporal_key is not None:
         s = "Temporal Key: %s\n" % binascii.hexlify(self.temporal_key).decode('ascii')

      return "PartialFile:\n\tInitial TXID: %s\n\tSanitized filename: %s\n\tDescription: %s\n\tFile size: %d\n\tEncryption type: %s\n\tContent type: %s\n\tCompression type: %s\n\t%s\n\tFile hash: %s\n\tFile pointer: %d\n\tACK Window: %s\n\t%s\n\tInitial block number: %d\n\tFinal block number: %d\n\tIs deadman switch file: %s\n\tIs deadman switch key: %s\n\tIs complete deadman switch file: %r\n\tIs complete: %r\n" % (self.initial_txid, self.sanitized_filename, self.description, self.file_size, Publication.get_encryption_str(self.encryption_type), Publication.get_content_type_str(self.content_type), Publication.get_compression_type_str(self.compression_type), general_flags_str, binascii.hexlify(self.file_hash).decode('ascii'), self.file_ptr, self.block_acks, s, self.initial_block_num, self.final_block_num, self.is_deadman_switch_file(), self.is_deadman_switch_key(), self.is_complete_deadman_switch_file(), self.is_complete())


   # Return a unique filepath to use for a new file, based on the TXID and
   # sanitized filename from the blockchain.
   @staticmethod
   def get_unique_filepath(txid, partial_dir, sanitized_filename):
      if sanitized_filename == '':
         sanitized_filename = "unnamed_file_%s" % txid[0:16]

      # Try to use the given filename in the blockchain first.
      unique_filepath = os.path.join(partial_dir, sanitized_filename)
      is_unique = False
      i = 0
      while is_unique is False:
         i += 1

         if not os.path.exists(unique_filepath):
            is_unique = True
         else:
            # If the given name is not unique, try the given name with "_0",
            # "_1", "_2", etc. appended until we finally find one that is
            # unique.
            unique_filepath = os.path.join(partial_dir, "%s_%d" % (sanitized_filename, i))

      return unique_filepath


   # Return a list of PartialFiles, loaded from disk.
   @staticmethod
   def load_state_files(d, partial_dir):
      partial_files = []

      for root, dirs, files in os.walk(partial_dir):
         for file in files:
            if file.endswith('.state'):
               state_file = os.path.join(root, file)
               d("Loading state file: %s" % state_file)
               with open(state_file, 'rb') as f:
                  partial_files.append(pickle.load(f))

      return partial_files
