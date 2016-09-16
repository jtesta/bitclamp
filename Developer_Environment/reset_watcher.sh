killall bitcoind 2> /dev/null
rm -rf ~/.bitcoin
mkdir ~/.bitcoin

RPCPASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
echo -e "rpcuser=bitcoin\nrpcpassword=$RPCPASS\nrpcport=8889\n" > ~/.bitcoin/bitcoin.conf
chmod 0600 ~/.bitcoin/bitcoin.conf

read -p "Enter the full path to blockchain_watcher.py: " SCRIPT_PATH
read -p "Enter the full path to the directory to store output: " OUTPUT_DIR

sed -i "s/^RPCPASS=.*$/RPCPASS=$RPCPASS/g" run_bitcoind_watcher.sh
sed -i "s,^BLOCKCHAIN_WATCHER_PATH=.*$,BLOCKCHAIN_WATCHER_PATH=$SCRIPT_PATH,g" run_bitcoind_watcher.sh
sed -i "s,^FILE_OUTPUT_DIR=.*$,FILE_OUTPUT_DIR=$OUTPUT_DIR,g" run_bitcoind_watcher.sh

echo
echo "Ensure that $SCRIPT_PATH is readable by the btcwatcher user."
echo "Done."
echo

