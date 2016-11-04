#!/bin/bash

# Run dogecoind if its not already running.
if [[ `dogecoin-cli getinfo 2>&1 | grep "couldn't connect to server"` != '' ]]; then
  dogecoind -regtest -daemon -port=18555 -acceptnonstdtxn=0 -txindex
fi
