#!/bin/bash

killall dogecoind 2> /dev/null
rm -rf ~/.dogecoin
mkdir -m 0700 ~/.dogecoin

# The Make target will set the script path and output directory via the
# arguments.  Otherwise, prompt the user.
if [[ $# == 2 ]]; then
  SCRIPT_PATH=$1
  OUTPUT_DIR=$2
else
  read -p "Enter the full path to blockchain_watcher.py: " SCRIPT_PATH
  read -p "Enter the full path to the directory to store output: " OUTPUT_DIR
fi

RPCPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo -e "rpcuser=dogecoin\nrpcpassword=$RPCPASS\nrpcport=7778\n" > ~/.dogecoin/dogecoin.conf
chmod 0600 ~/.dogecoin/dogecoin.conf

sed -i "s/^RPCPASS=.*$/RPCPASS=$RPCPASS/g" doge_run_dogecoind_reader.sh
sed -i "s,^BLOCKCHAIN_WATCHER_PATH=.*$,BLOCKCHAIN_WATCHER_PATH=$SCRIPT_PATH,g" doge_run_dogecoind_reader.sh
sed -i "s,^FILE_OUTPUT_DIR=.*$,FILE_OUTPUT_DIR=$OUTPUT_DIR,g" doge_run_dogecoind_reader.sh

echo
echo "Ensure that $SCRIPT_PATH is readable by the dogereader user."
echo "Done."
echo

