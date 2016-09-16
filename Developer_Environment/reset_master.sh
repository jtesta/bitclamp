#!/bin/bash

killall bitcoind 2> /dev/null
rm -rf ~/.bitcoin
mkdir ~/.bitcoin

RPCPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo -e "rpcuser=bitcoin\nrpcpassword=$RPCPASS\nrpcport=8888\n" > ~/.bitcoin/bitcoin.conf
chmod 0600 ~/.bitcoin/bitcoin.conf

sed -i "s/^RPCPASS=.*$/RPCPASS=$RPCPASS/g" run_bitcoind_master.sh

