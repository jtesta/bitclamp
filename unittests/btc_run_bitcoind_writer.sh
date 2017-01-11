#!/bin/bash

BLOCK_CLIENT_PATH=[STUFF GOES HERE]
LISTENER_PATH=[STUFF GOES HERE]

# Run bitcoind if its not already running.
if [[ `bitcoin-cli getinfo 2>&1 | grep "couldn't connect to server"` != '' ]]; then
  bitcoind -regtest -daemon -acceptnonstdtxn=0 -txindex -blocknotify="python3 $BLOCK_CLIENT_PATH $LISTENER_PATH"
fi
