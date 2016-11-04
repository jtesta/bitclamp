#!/bin/bash

# Run bitcoind if its not already running.
if [[ `bitcoin-cli getinfo 2>&1 | grep "couldn't connect to server"` != '' ]]; then
  bitcoind -regtest -daemon -acceptnonstdtxn=0 -txindex
fi
