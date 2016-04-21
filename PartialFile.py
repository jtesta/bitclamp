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

import binascii, hashlib, mmap, os, pickle

class PartialFile:
   def __init__(self, debug_func, initial_txid, output_dir, partial_dir, sanitized_filename, description, file_size, general_flags, content_type, compression_type, file_hash):
      self.debug_func = debug_func
      self.initial_txid = initial_txid
      self.output_dir = output_dir
      self.sanitized_filename = sanitized_filename
      self.description = description
      self.file_size = file_size
      self.general_flags = general_flags
      self.content_type = content_type
      self.compression_type = compression_type
      self.file_hash = file_hash

      self.file_path = PartialFile.get_unique_filepath(initial_txid, partial_dir, sanitized_filename)
      self.state_file = self.file_path + '.state'

      self.file_ptr = 0
      self.block_acks = {}
      self.previous_txid = self.initial_txid
      self.temporal_key = None
      self.finalized = False


   def d(self, s):
      self.debug_func(s)


   def get_previous_txid(self):
      return self.previous_txid


   def set_previous_txid(self, previous_txid):
      self.previous_txid = previous_txid


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


      if offset + len(data) > self.file_size:
         truncated_len = self.file_size - offset
         data = data[0:truncated_len]

         self.d("Offset (%d) + data length (%d) is greater than file size (%d). Truncated data to %d" % (offset, len(data), self.file_size, truncated_len))

         

      with open(self.file_path, 'a+b') as f:
         data_len = len(data)

         f.seek(0, os.SEEK_END)
         size = f.tell()
         if offset + data_len > size:
            change = (offset + data_len - size)
            self.d("Enlarging the file by %d bytes." % change)
            f.write(b'\x00' * change)
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


   def is_deadman_switch(self):
      from Publication import Publication

      return True if (self.general_flags & Publication.GENERAL_FLAG_DEADMAN_SWITCH) == Publication.GENERAL_FLAG_DEADMAN_SWITCH else False


   # Returns True if this file is completely published, or False.
   def is_complete(self):
      return True if self.file_ptr == self.file_size else False


   # Decrypts the file, if necessary.
   def finalize(self, num_parallel_txs, encryption_type, temporal_key):
      from Publication import Publication
      from Utils import Utils

      # If not all bytes were received, this is a failure.
      if not self.is_complete():
         self.d("Cannot finalize because file is not complete!")
         return False

      # Update the temporal key, if there is one.
      if (encryption_type != Publication.ENCRYPTION_TYPE_NONE) and \
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
         self.d("Hashes do not match!:\n%s\n%s" % (binascii.hexlify(self.file_hash), binascii.hexlify(calculated_hash)))
         return False

      # If this file is a deadman switch, don't try to decrypt, since we don't
      # have the real key here.
      if self.is_deadman_switch():
         return True

      # Get a unique filename in the output directory.
      new_file_path = PartialFile.get_unique_filepath(self.initial_txid, self.output_dir, self.sanitized_filename)

      # Decrypt the file, if necessary.
      if encryption_type == Publication.ENCRYPTION_TYPE_GPG2_AES256_SHA512:
         self.d("File is encrypted with type %s.  Decrypting..." % Publication.get_encryption_str(encryption_type))
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

      # Mark as finalized and return success.
      self.finalized = True
      return True


   def __str__(self):
      import base64
      from Publication import Publication

      s = ''
      if self.temporal_key is not None:
         s = "Temporal Key: %s\n" % base64.b64encode(self.temporal_key).decode('ascii').strip()

      return "PartialFile:\n\tInitial TXID: %s\n\tSanitized filename: %s\n\tDescription: %s\n\tFile size: %d\n\tContent type: %s\n\tCompression type: %s\n\tFile hash: %s\n\tFile pointer: %d\n\tACK Window: %s\n\t%s\n\tDeadman switch: %s\n\tComplete: %r\n" % (self.initial_txid, self.sanitized_filename, self.description, self.file_size, Publication.get_content_str(self.content_type), Publication.get_compression_str(self.compression_type), binascii.hexlify(self.file_hash).decode('utf-8'), self.file_ptr, self.block_acks, s, self.is_deadman_switch(), self.is_complete())


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
