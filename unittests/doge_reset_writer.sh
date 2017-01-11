#!/bin/bash

if [[ $# == 2 ]]; then
  BLOCK_CLIENT_PATH=$1
  LISTENER_PATH=$2
else
  read -p "Enter the full path to BlockClient.py: " BLOCK_CLIENT_PATH
  read -p "Enter the full path to the file to store the listener endpoints: " LISTENER_PATH
fi

rm -f $LISTENER_PATH
touch $LISTENER_PATH

killall dogecoind 2> /dev/null
rm -rf ~/.dogecoin ~/tmp
mkdir -m 0700 ~/.dogecoin ~/tmp

RPCPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo -e "rpcuser=dogecoin\nrpcpassword=$RPCPASS\nrpcport=7777\n" > ~/.dogecoin/dogecoin.conf
chmod 0600 ~/.dogecoin/dogecoin.conf

sed -i "s,^BLOCK_CLIENT_PATH=.*$,BLOCK_CLIENT_PATH=$BLOCK_CLIENT_PATH,g" doge_run_dogecoind_writer.sh
sed -i "s,^LISTENER_PATH=.*$,LISTENER_PATH=$LISTENER_PATH,g" doge_run_dogecoind_writer.sh
