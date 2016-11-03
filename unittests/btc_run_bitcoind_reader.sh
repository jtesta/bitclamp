#!/bin/bash

RPCPASS=[STUFF GOES HERE]
BLOCKCHAIN_WATCHER_PATH=[STUFF GOES HERE]
FILE_OUTPUT_DIR=[STUFF GOES HERE]

# Run bitcoind if its not already running.
if [[ `bitcoin-cli getinfo 2>&1 | grep "couldn't connect to server"` != '' ]]; then
  bitcoind -regtest -daemon -listen=0 -acceptnonstdtxn=0 -addnode=localhost -txindex -blocknotify="python3 $BLOCKCHAIN_WATCHER_PATH localhost 8889 bitcoin $RPCPASS $FILE_OUTPUT_DIR $FILE_OUTPUT_DIR/log.txt %s -d"
fi

