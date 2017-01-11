#!/bin/bash

# This resets and re-initializes the blockchain for the writer.

if [[ $# == 2 ]]; then
  BLOCK_CLIENT_PATH=$1
  LISTENER_PATH=$2
else
  read -p "Enter the full path to BlockClient.py: " BLOCK_CLIENT_PATH
  read -p "Enter the full path to the file to store the listener endpoints: " LISTENER_PATH
fi

rm -f $LISTENER_PATH
touch $LISTENER_PATH

killall bitcoind 2> /dev/null
rm -rf ~/.bitcoin ~/tmp
mkdir -m 0700 ~/.bitcoin ~/tmp

RPCPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo -e "rpcuser=bitcoin\nrpcpassword=$RPCPASS\nrpcport=8888\n" > ~/.bitcoin/bitcoin.conf
chmod 0600 ~/.bitcoin/bitcoin.conf

sed -i "s,^BLOCK_CLIENT_PATH=.*$,BLOCK_CLIENT_PATH=$BLOCK_CLIENT_PATH,g" btc_run_bitcoind_writer.sh
sed -i "s,^LISTENER_PATH=.*$,LISTENER_PATH=$LISTENER_PATH,g" btc_run_bitcoind_writer.sh
