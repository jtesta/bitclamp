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


# This class performs RPC calls to the Bitcoin RPC server.  These methods are
# a subset of what are available from the 'bitcoin-cli' command-line tool.

import base64, json, urllib.request
from Utils import *

class RPCClient:

    def __init__(self, hostname, port, username, password):
        self.hostname = hostname
        self.port = int(port)

        # Set up the credentials for HTTP Basic authentication.
        creds = '%s:%s' % (username, password)
        self.basic_auth = 'Basic ' + base64.b64encode(creds.encode('ascii')).decode('ascii')

        if (self.hostname != 'localhost') and (self.hostname != '127.0.0.1'):
            raise Exception('hostname must be localhost or 127.0.0.1 since HTTPS is not supported!')

        self.url = 'http://%s:%d/' % (self.hostname, self.port)
        self.config_file = None


    def send_request(self, method, params=[]):

        # If a dict was passed, convert it to a string.
        if not isinstance(params, str):
            params = json.dumps(params)

        data = '{"id":1,"method":"%s","params":%s}' % (method, params)
        request = urllib.request.Request(self.url, data.encode('utf-8'), {'Content-Type':'application/json','Authorization':self.basic_auth,'Accept':'application/json'})
        response = urllib.request.urlopen(request, None, 30)
        response_json = json.loads(response.read().decode('utf-8'))
        return response_json['result']


    # This function is different.  Instead of taking two dictionaries, both
    # arguments must be strings.  This is because the order of entries in
    # 'outputs' must be preserved; if a dictionary is used, the order is often
    # changed, which breaks the order of file data.
    def createrawtransaction(self, inputs, outputs):
        return self.send_request('createrawtransaction', "[%s,%s]" % (inputs, outputs))


    def decoderawtransaction(self, raw_tx):
        return self.send_request('decoderawtransaction', [raw_tx])


    def dumpprivkey(self, address):
        return self.send_request('dumpprivkey', [address])


    def estimatefee(self, n):
        return float(self.send_request('estimatefee', [n]))


    def getblock(self, block_hash):
        return self.send_request('getblock', [block_hash])


    def getblockchaininfo(self):
        return self.send_request('getblockchaininfo')


    def getblockcount(self):
        return int(self.send_request('getblockcount'))


    def getblockhash(self, index):
        return self.send_request('getblockhash', [index])


    def getconnectioncount(self):
        return int(self.send_request('getconnectioncount'))


    def getnewaddress(self):
        return self.send_request('getnewaddress')


    def getrawtransaction(self, txid, verbose):
        return self.send_request('getrawtransaction', [txid, verbose])


    def sendrawtransaction(self, txbytes):
        return self.send_request('sendrawtransaction', [txbytes])


    def signrawtransaction(self, raw_tx, stuffs, privkey):
        return self.send_request('signrawtransaction', [raw_tx, stuffs, [privkey]])

    def stop(self):
        return self.send_request('stop')


    def validateaddress(self, address):
        return self.send_request('validateaddress', [address])


    # Creates and returns a new RPCClient using credentials from the
    # bitcoin.conf/dogecoin.conf configuration file.  The 'chain' argument must
    # be either 'btc' or 'doge' to determine which to use.
    @staticmethod
    def init_from_config_file(chain):
        from os.path import expanduser

        # Get the path to the config file.
        config_file = "%s/.bitcoin/bitcoin.conf" % expanduser("~")
        if chain == 'doge':
            config_file = "%s/.dogecoin/dogecoin.conf" % expanduser("~")

        rpchost, rpcport, rpcuser, rpcpass = Utils.parse_config_file(config_file)
        if rpcport is None:
            if chain == 'doge':
                rpcport = 22555
            else:
                rpcport = 8332

        rpc_client = RPCClient(rpchost, rpcport, rpcuser, rpcpass)
        rpc_client.config_file = config_file
        return rpc_client
