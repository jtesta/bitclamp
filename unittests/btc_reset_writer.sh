#!/bin/bash

# This resets and re-initializes the blockchain for the writer.

killall bitcoind 2> /dev/null
rm -rf ~/.bitcoin ~/tmp
mkdir -m 0700 ~/.bitcoin ~/tmp

RPCPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo -e "rpcuser=bitcoin\nrpcpassword=$RPCPASS\nrpcport=8888\n" > ~/.bitcoin/bitcoin.conf
chmod 0600 ~/.bitcoin/bitcoin.conf

