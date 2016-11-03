#!/bin/bash

RPCPASS=[STUFF GOES HERE]
BLOCKCHAIN_WATCHER_PATH=[STUFF GOES HERE]
FILE_OUTPUT_DIR=[STUFF GOES HERE]

# Run dogecoind if its not already running.
if [[ `dogecoin-cli getinfo 2>&1 | grep "couldn't connect to server"` != '' ]]; then
  dogecoind -regtest -daemon -listen=0 -acceptnonstdtxn=0 -addnode=localhost:18555 -txindex -blocknotify="python3 $BLOCKCHAIN_WATCHER_PATH localhost 7778 dogecoin $RPCPASS $FILE_OUTPUT_DIR $FILE_OUTPUT_DIR/log.txt %s -d"
fi

