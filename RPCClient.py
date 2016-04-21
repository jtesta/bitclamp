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

class RPCClient:

    def __init__(self, hostname, port, username, password):
        self.hostname = hostname
        self.port = int(port)

        # Set up the credentials for HTTP Basic authentication.
        creds = '%s:%s' % (username, password)
        self.basic_auth = 'Basic ' + base64.b64encode(creds.encode('ascii')).decode('ascii')
        self.url = 'http://%s:%d/' % (self.hostname, self.port)


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


    def dumpprivkey(self, address):
        return self.send_request('dumpprivkey', [address])


    def estimatefee(self, n):
        return float(self.send_request('estimatefee', [n]))


    def getbestblockhash(self):
        return self.send_request('getbestblockhash')


    def getblock(self, block_hash):
        return self.send_request('getblock', [block_hash])


    def getblockcount(self):
        return int(self.send_request('getblockcount'))


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


    def validateaddress(self, address):
        return self.send_request('validateaddress', [address])
