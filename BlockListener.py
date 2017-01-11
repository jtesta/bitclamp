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

import socket, threading

class BlockListener:


    # The constructor takes a debugging log function and an RPCClient object.
    def __init__(self, debug_log_function, rpc_client):
        self.d = debug_log_function
        self.rpc_client = rpc_client

        self.block_hash_list = []
        self.block_hash_list_condition = threading.Condition()
        self.server_socket = None
        self.server_thread = None
        self.port = None

        # When set to True, this Listener will start parsing new blocks.
        # Initially set to False so blocks that come in during synchronization
        # of the blockchain are ignored.
        self.process_blocks = False


    # Starts the listener.  It will attempt to use TCP port 4761, and keep
    # incrementing until successful.
    def start_listener(self):
        from random import random

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind to TCP port 4761.  Keep incrementing until successful.
        initial_port = 4761
        port = initial_port
        bind_not_successful = True
        while bind_not_successful:
            try:
                self.server_socket.bind(('127.0.0.1', port))
                bind_not_successful = False
            except socket.error as e:
                port += 1
                if (port - initial_port) > 128:
                    break

        # Make sure that the bind was successful.
        if bind_not_successful:
            raise RuntimeError('BlockListener: failed to find available port to listen on!: %d - %d' % (initial_port, port))

        self.port = port

        # Begin listening on the socket, and spawn a server thread for new
        # incoming connections.
        self.server_socket.listen(64)
        self.server_thread = threading.Thread(name='Server Thread', target=BlockListener._start_listener, args=(self,), daemon=True)
        self.server_thread.start()


    # Called by the server thread to handle incoming connections.
    def _start_listener(self):
        try:
            while True:
                conn, addr = self.server_socket.accept()
                client_thread = threading.Thread(name='Client Thread (%s: %d)' % (addr[0], addr[1]), target=BlockListener.handle_client, args=(self, conn,), daemon=True)
                client_thread.start()
        except Exception as e:
            self.d('Exception in _start_listener(): %s' % str(e))


    # Called by new thread to handle a new client connection.
    def handle_client(self, conn):
        conn.settimeout(10)

        # The client starts by sending one byte.  We respond by sending one
        # byte back.
        try:
            if conn.recv(1) == b'J':
                conn.send(b'T')
        except Exception as e:
            pass

        # Make sure that the socket is closed now, either after a successful
        # read, or after an error.
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            pass


        # If we're not set to process block hashes, then just return.  This
        # happens when the daemon is still syncing up upon initialization.
        if self.process_blocks is False:
            return


        # Acquire the block hash list lock.
        self.block_hash_list_condition.acquire()

        # Get the total number of blocks from the daemon.  If this doesn't
        # match the latest block we know about, increment our latest block
        # number, get its corresponding hash, and append it to the hash list.
        # Continue incrementing until we hit the block count.
        appended_hash = False
        block_count = self.rpc_client.getblockcount()
        while self.latest_block_count < block_count:
            self.latest_block_count += 1
            self.block_hash_list.append(self.rpc_client.getblockhash(self.latest_block_count))
            appended_hash = True

        # If we added at least one hash to the list, wake up a blocked caller.
        if appended_hash:
            self.block_hash_list_condition.notify()

        self.block_hash_list_condition.release()


    # Tell this BlockListener that the blockchain has finished synchronizing,
    # and that it should start processing blocks.
    def begin_processing(self):
        self.latest_block_count = self.rpc_client.getblockcount()
        self.process_blocks = True


    # Returns a list of new block hashes immediately (if available), or hangs
    # until a list with at least one block hash is available.
    def wait_for_blocks(self):
        ret = None

        self.block_hash_list_condition.acquire()

        # If the list is empty, block until a client thread adds a block hash
        # and wakes us up.
        if len(self.block_hash_list) == 0:
            self.block_hash_list_condition.wait()

        # Keep the reference to the list, and create a new, empty list.
        ret = self.block_hash_list
        self.block_hash_list = []

        self.block_hash_list_condition.release()
        return ret
