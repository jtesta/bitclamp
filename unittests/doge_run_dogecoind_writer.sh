#!/bin/bash

BLOCK_CLIENT_PATH=[STUFF GOES HERE]
LISTENER_PATH=[STUFF GOES HERE]

# Run dogecoind if its not already running.
if [[ `dogecoin-cli getinfo 2>&1 | grep "couldn't connect to server"` != '' ]]; then
  dogecoind -regtest -daemon -port=18555 -acceptnonstdtxn=0 -txindex -blocknotify="python3 $BLOCK_CLIENT_PATH $LISTENER_PATH"
fi
