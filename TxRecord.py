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


# This class maintains information for an individual transaction, such as the
# TXID, redeem scripts, P2SH addresses, TXID and number of confirmations.
class TxRecord:
    def __init__(self, redeem_scripts, p2sh_addresses, num_bytes):
        self.redeem_scripts = redeem_scripts
        self.p2sh_addresses = p2sh_addresses
        self.num_bytes = num_bytes

        self.txid = None
        self.confirmations = 0
        self.output_scripts = []
        self.vout_nums = []
        self.values = []
        self.last_record = False
        self.total_amount = -1.0

    # Sets the TXID.
    def set_txid(self, txid):
        self.txid = txid

    # Updates the number of confirmations.  Note that this can decrease
    # occasionally if blocks are rolled back.
    def set_confirmations(self, confirmations):
        self.confirmations = int(confirmations)

    def add_output_script(self, output_script):
        self.output_scripts.append(output_script)

    def add_vout_num(self, vout_num):
        self.vout_nums.append(vout_num)

    def add_value(self, value):
        self.values.append(value)

    def get_txid(self):
        return self.txid

    def get_confirmations(self):
        return self.confirmations

    def get_output_scripts(self):
        return self.output_scripts

    def get_vout_nums(self):
        return self.vout_nums

    def get_values(self):
        return self.values

    def set_last_record(self):
        self.last_record = True    

    def is_last_record(self):
        return self.last_record

    def get_total_amount(self):
        return self.total_amount

    def set_total_amount(self, amount):
        self.total_amount = amount

    # Returns a string representation of this TxRecord.
    def __str__(self):
        txid = self.txid
        if txid is None:
            txid = 'None'

        vout_nums = ''
        for vout_num in self.get_vout_nums():
            vout_nums = vout_nums + "%d, " % vout_num
        if len(vout_nums) > 2:
            vout_nums = vout_nums[:-2]

        values = ''
        for value in self.get_values():
            values = values + "%.8f, " % value
        if len(values) > 2:
            values = values[:-2]

        return 'TxRecord: %s; Confirmations: %d; P2SH Addresses: %s; Output scripts: %s; vout nums: %s; Values: %s; Last Flag: %r' % (txid, self.confirmations, ', '.join(self.p2sh_addresses), ', '.join(self.output_scripts), vout_nums, values, self.last_record)
