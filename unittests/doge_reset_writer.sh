#!/bin/bash

killall dogecoind 2> /dev/null
rm -rf ~/.dogecoin ~/tmp
mkdir -m 0700 ~/.dogecoin ~/tmp

RPCPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo -e "rpcuser=dogecoin\nrpcpassword=$RPCPASS\nrpcport=7777\n" > ~/.dogecoin/dogecoin.conf
chmod 0600 ~/.dogecoin/dogecoin.conf
