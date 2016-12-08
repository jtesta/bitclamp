#!/bin/bash

# This resets and re-initializes the blockchain for the reader.

killall bitcoind 2> /dev/null
rm -rf ~/.bitcoin
mkdir -m 0700 ~/.bitcoin

# The unittests Make target will set the script path and output directory via
# the arguments.  Otherwise, prompt the user.
if [[ $# == 3 ]]; then
  SCRIPT_PATH=$1
  OUTPUT_DIR=$2
  SQLITE3_PATH=$3
else
  read -p "Enter the full path to blockchain_watcher.py: " SCRIPT_PATH
  read -p "Enter the full path to the directory to store output: " OUTPUT_DIR
  read -p "Enter the full path to the SQLite3 database (or where you'd like it to be stored if it doesn't exist): " SQLITE3_PATH
fi

RPCPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo -e "rpcuser=bitcoin\nrpcpassword=$RPCPASS\nrpcport=8889\n" > ~/.bitcoin/bitcoin.conf
chmod 0600 ~/.bitcoin/bitcoin.conf

sed -i "s,^BLOCKCHAIN_WATCHER_PATH=.*$,BLOCKCHAIN_WATCHER_PATH=$SCRIPT_PATH,g" btc_run_bitcoind_reader.sh
sed -i "s,^FILE_OUTPUT_DIR=.*$,FILE_OUTPUT_DIR=$OUTPUT_DIR,g" btc_run_bitcoind_reader.sh
sed -i "s,^SQLITE3_PATH=.*$,SQLITE3_PATH=$SQLITE3_PATH,g" btc_run_bitcoind_reader.sh

echo
echo "Ensure that $SCRIPT_PATH is readable by the btcreader user."
echo "Done."
echo
