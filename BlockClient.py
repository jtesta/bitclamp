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

import fcntl, socket, sys, time


# Sends a ping to a BlockListener to signify that a new block is available.
def send_ping(host, port, endpoints, index, lock):
    fail_count = 0
    sock = None
    complete = False

    # Try to send the ping up to two times.
    while not complete and (fail_count < 2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
        except OSError as e:
            print('BlockClient: failed to connect: %d: %s' % (port, str(e)))
            fail_count += 1
            if fail_count < 2:
                time.sleep(1)
            continue

        # Send a single byte to ping the BlockListener.
        n = 0
        try:
            n = sock.send(b'J')
        except OSError as e:
            print('BlockClient: failed to send: %d: %s' % (port, str(e)))
            pass

        # If the send failed, don't bother trying to receive the ACK.
        if n == 0:
            fail_count += 1
        else:
            # Get a one-byte ACK from the BlockListener.
            try:
                if sock.recv(1) == b'T':
                    complete = True
                else:
                    fail_count += 1
            except Exception as e:
                print('BlockClient: failed to receive: %d: %s' % (port, str(e)))
                fail_count += 1

        # Close the socket.
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            pass

        if not complete and fail_count < 2:
            time.sleep(fail_count)


    if endpoints is not None:
        lock.acquire()
        endpoints[index]['result'] = complete
        lock.release()

    if not complete:
        print('BlockClient: send_ping() failed: %d' % port)

    return complete


if __name__ == '__main__':

    # If run with two arguments, they signify a single host and port.
    # Example:  "python3 BlockClient localhost 4761"
    if len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])

        send_ping(host, port, None, None, None)

    # If run with one argument, this is a file that contains a list of
    # BlockListeners.  The file has the format of:
    # "hostname port failure_count failure_timestamp".  The failure_count
    # starts at 0 and is updated by this program when a failure occurs.  The
    # failure_timestamp tracks the last time (in seconds since the epoch)
    # since an error occurred.  An endpoint is automatically purged after 3
    # consecutive failures (multiple failures within a 5-second interval are
    # only counted as 1 failure; this is why a timestamp is tracked).
    #
    # Example file format:
    # localhost 4761 0 0
    # localhost 4762 0 0
    
    elif len(sys.argv) == 2:
        import threading

        endpoint_file = sys.argv[1]
        
        fd = None
        try:

            # Open the endpoint file and obtain an exclusive lock on it,
            # as other concurrent BlockClients may be running.
            fd = open(endpoint_file, 'r+')
            fcntl.lockf(fd, fcntl.LOCK_EX)

            lines = fd.readlines()

            endpoints = []
            for line in lines:

                # Parse each line in the file.  If it has four fields, then
                # it is properly formatted.
                t = line.split(' ')
                if len(t) == 4:
                    endpoints.append({'host': t[0].strip(), 'port': int(t[1]), 'failures': int(t[2]), 'last_fail_time': int(t[3])})

                # If this line has two fields, then a human probably added it.
                # Assume the failures and failure timestamp are both 0.
                elif len(t) == 2:
                    endpoints.append({'host': t[0].strip(), 'port': int(t[1]), 'failures': 0, 'last_fail_time': 0})
                else:
                    continue

            # Spawn a thread for each endpoint in the file.  Each thread will
            # call send_ping() to notify the BlockListener in parallel.
            lock = threading.Lock()
            for endpoint in endpoints:
                host = endpoint['host']
                port = endpoint['port']
                endpoint['thread'] = threading.Thread(name='send_ping(%s, %d)' % (host, port), target=send_ping, args=(host, port, endpoints, endpoints.index(endpoint), lock), daemon=True)
                endpoint['thread'].start()

            # Get the return value of send_ping() from each thread.  Update
            # our data structure to write back into the file, if necessary.
            file_needs_updating = False
            for endpoint in endpoints:
                endpoint['thread'].join()
                result = endpoint['result']

                # Only count this failure if the last one happened more than
                # 5 seconds ago.
                if result == False and (time.time() - endpoint['last_fail_time']) > 5:
                    endpoint['failures'] += 1
                    endpoint['last_fail_time'] = int(time.time())

                    file_needs_updating = True

                # If send_ping() returned True, but the endpoint had a previous
                # failure, reset the count back to 0.
                elif result == True and endpoint['failures'] > 0:
                    endpoint['failures'] = 0
                    endpoint['last_fail_time'] = 0
                    file_needs_updating = True

            # If the endpoint information changed above, we need to update
            # the file.
            if file_needs_updating:
                fd.seek(0, 0)
                fd.truncate(0)

                # Overwrite the file with all the endpoint data we have.  If
                # an endpoint has 3 or more failures, purge it.  That listener
                # is probably dead.
                for e in endpoints:
                    if e['failures'] < 3:
                        fd.write("%s %d %d %d\n" % (e['host'], e['port'], e['failures'], e['last_fail_time']))
                    else:
                        print('BlockClient: purging port %d.' % e['port'])

            fd.close()
        except Exception as e:
            print('Exception in BlockClient: %s' % str(e))
            if fd is not None:
                fd.close()
