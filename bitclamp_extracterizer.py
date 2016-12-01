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


# This program extracts data from the blockchain, given certain filter
# arguments.

import argparse, sys
from BlockParser import *
from ContentFilter import *
from RPCClient import *

# These are the block numbers where content was first published.
BTC_FIRST_CONTENT_BLOCK = 437500
DOGE_FIRST_CONTENT_BLOCK = 1451000

debug = False
verbose = False

def d(s):
    if debug:
        print(s)

def log(s):
    if verbose:
        print(s)

# Ensure that the wildcard character is only at the beginning or at the end
# of the filename.  Terminates if inappropriate wildcard is found.
def check_wildcard(s):
    if s is not None:
        last_star_pos = 0
        star_pos = s.find('*')
        while star_pos != -1:
            if (star_pos > 0 and star_pos < len(s) - 1):
                print("Error: wildcard must come at beginning and/or end of string only: %s" % s)
                exit(-1)

            last_star_pos = star_pos
            star_pos = s.find('*', last_star_pos + 1)


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--regtest', help='enable regression test mode (for debugging & development only)', action='store_true')
    parser.add_argument('--chain', help='the blockchain to use ("btc" or "doge"; default: "btc")', default='btc')
    parser.add_argument('--start-block', help='the block number to begin scanning for content', type=int)
    parser.add_argument('--end-block', help='the block number up to which scanning should be done for content', type=int)
    parser.add_argument('--filename', help='a filename to filter on.  May contain a * wildcard character either prepended or appended')
    parser.add_argument('--description', help='a description to filter on.  May contain a * wildcard character either prepended or appended')
    parser.add_argument('--content-type', help='a content type to filter on.  Acceptable values: document, picture, sound, video, sourcecode, digitalsignature, archive, undefined.  May be specified several times to extract multiple types simultaneously', action='append')
    parser.add_argument('--output', help='the output directory to store discovered content in')
    parser.add_argument('--keep-partial', help='keep partially extracted files', action='store_true')
    parser.add_argument('--keep-deadmen', help='keep deadman switch files (i.e.: encrypted files for which no keys have yet been published)', action='store_true')

    parser.add_argument('--verbose', help='enables verbose output.', action='store_true')
    parser.add_argument('--debug', help='enables debugging output (implies --verbose).', action='store_true')

    args = vars(parser.parse_args())

    regtest = args['regtest']
    chain = args['chain']
    start_block = args['start_block']
    end_block = args['end_block']
    filename = args['filename']
    description = args['description']
    content_type_list = args['content_type']
    output_dir = args['output']
    keep_partial = args['keep_partial']
    keep_deadmen = args['keep_deadmen']
    verbose = args['verbose']
    debug = args['debug']

    if debug:
        verbose = True

    # Check that any wildcard characters exist at the very beginning and/or
    # very end only.
    check_wildcard(filename)
    check_wildcard(description)

    # If a content type filter list was given, resolve each string.
    resolved_content_type_list = None
    if content_type_list is not None:
        resolved_content_type_list = []
        for content_type in content_type_list:
            content_type_const = Publication.get_content_type_const(content_type)
            if content_type_const is False:
                valid_content_types = list(Publication.CONTENT_TYPE_MAP.values())
                valid_content_types.remove('auto')
                print("Error: %s is not a valid content type.  Valid content types are: %s." % (content_type, ', '.join(valid_content_types)))
                exit(-1)

            # If the content type is valid, add its Publication.CONTENT_TYPE_*
            # constant to this list.  This is given to the ContentFilter later.
            else:
                resolved_content_type_list.append(content_type_const)


    # Ensure that the output directory is specified.
    if output_dir is None:
        print('Error: --output must be specified.')
        exit(-1)

    # Create the RPCClient from the local config file.
    rpc_client = RPCClient.init_from_config_file(chain)

    # If we're not using the regtest network, ensure that the start block isn't
    # before the first known block of content.
    if regtest is False:
        first_block = BTC_FIRST_CONTENT_BLOCK
        if chain == 'doge':
            first_block = DOGE_FIRST_CONTENT_BLOCK

        if (start_block is not None) and (start_block < first_block):
            print('Warning: start block is before first known block containing content (%d) on the %s network.  Using %d instead.' % (first_block, chain.upper(), first_block))
            start_block = first_block


    # Ensure that the end block comes after the start block.
    if (start_block is not None) and (end_block is not None) and (end_block < start_block):
        print("Error: end block (%d) must come after the start block (%d)!" % (end_block, start_block))
        exit(-1)

    # Ensure that the end block is not past the total block count.
    blockcount = rpc_client.getblockcount()
    if (end_block is not None) and (blockcount < end_block):
        print('Warning: end block (%d) is after the last block (%d) in the %s blockchain.  Using %d instead.' % (end_block, blockcount, chain.upper(), blockcount))
        end_block = blockcount

    # If the start block is not specified or is 0, set it to 1.
    if (start_block is None) or (start_block == 0):
        # Block 0 is valid, but querying its transactions results in a strange
        # error...
        start_block = 1

    # If the end block is not specified, set it to the last known block.
    if end_block is None:
        end_block = blockcount

    # Create the partial directory within the output directory if it does not
    # already exist.
    partial_dir = os.path.join(output_dir, 'partial/')
    if not os.path.isdir(partial_dir):
        os.makedirs(partial_dir) # TODO: check umask!

    # Create a content filter based on what the user is searching for.
    content_filter = ContentFilter(filename, description, resolved_content_type_list)

    # Initialize the BlockParser with the debugging & logging functions,
    # RPCClient, output & partial directories, and content filter.
    BlockParser.init(d, log, rpc_client, output_dir, partial_dir, content_filter)

    current_block_num = start_block
    while current_block_num <= end_block:

        # Get the block hash from its number.
        current_block_hash = rpc_client.getblockhash(current_block_num)

        # Get information on the block from its hash.
        block_info = rpc_client.getblock(current_block_hash)

        # Now that we have its number, hash, and basic info, pass it off to the
        # BlockParser to process.
        BlockParser.parse_block(current_block_num, current_block_hash, block_info)

        current_block_num += 1

    # If the user wants to keep the deadman switch files, we need to go through
    # all the partial files and see which ones are applicable.
    if keep_deadmen:
        partial_files = PartialFile.load_state_files(d, partial_dir)
        for partial_file in partial_files:

            # If this is a complete deadman switch file...
            if partial_file.is_complete_deadman_switch_file():

                # Get a unique filename with respect to the output directory.
                filename = PartialFile.get_unique_filepath(partial_file.initial_txid, output_dir, 'deadman_switch_%s' % partial_file.sanitized_filename)

                # Move the deadman switch file out of the partial directory into
                # the output directory.
                os.rename(partial_file.file_path, filename)


    # If the partial directory exists and is empty, delete it.
    if os.path.isdir(partial_dir) and (os.listdir(partial_dir) == []):
            os.rmdir(partial_dir)


    # If the user didn't specify to keep the partial directory, and if it
    # exists, then delete it.
    if not keep_partial:
        if os.path.isdir(partial_dir):
            d('Deleting partial directory %s...' % partial_dir)

            from shutil import rmtree
            rmtree(partial_dir)
    elif os.path.isdir(partial_dir):
        d('Keeping partial directory %s...' % partial_dir)
