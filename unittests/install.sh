#!/bin/bash

# This script will install the unit test environment.

PROJECT_BASE_DIR=$1

# If the unit test environment is already installed, quit.
X=`id btcwriter > /dev/null 2> /dev/null`
if [[ $? == 0 ]]; then
  echo "It appears that the unit test environment is already installed."
  exit 0
fi

# Prompt the user before installing anything.
echo
echo -n "This script sets up the unit testing framework.  It was designed to be used in an isolated, dedicated virtual machine *ONLY*.  The framework performs some operations with root privileges, which may interfere with other processes.

Additionally, the following prerequisites must be met:

  * The VM must have at least 4GB of RAM.
  * Bitcoin Classic or Bitcoin Core must be installed (Classic is preferred).
  * Dogecoin must be installed.

Proceed? [y/N] "
read yn

if [[ $yn != 'y' ]]; then
  echo "Terminating installation without making any changes."
  exit 0
fi

# Ensure that at least 4GB of RAM exists.  On systems with exactly 4GB, 'free'
# returns 3951 here, for some reason...
total_ram=`free -m | grep Mem | gawk '{print $2}'`
if [[ $total_ram < 3900 ]]; then
  echo "This machine has less than 4GB of RAM.  Running the unit tests with insufficient memory is known to cause severe swap thrashing, which makes testing useless.  Increase the RAM and try again."
  exit 0
fi

# We need root privileges to create users.
if [[ `whoami` != 'root' ]]; then
  echo "You must be root to run this."
  exit -1
fi

# Check if Bitcoin Classic or Bitcoin Core is installed.
X=`which bitcoin-cli`
if [[ $? != 0 ]]; then
  echo "Can't find bitcoin-cli.  Install Bitcoin Classic manually to continue: https://bitcoinclassic.com/"
  echo $?
  exit -1
fi

# Ensure that Dogecoin is installed.
X=`which dogecoin-cli`
if [[ $? != 0 ]]; then
  echo "Can't find dogecoin-cli.  Install Dogecoin manually to continue: http://dogecoin.com/"
  echo $?
  exit -1
fi

# Ensure that gnupg2 and zip are both installed.
apt install -y gnupg2 zip > /dev/null 2> /dev/null

# Create the btcwriter, btcreader, dogewriter, and dogereader users.
useradd -m btcwriter && useradd -m btcreader && useradd -m dogewriter && useradd -m dogereader
chmod 0700 ~btcwriter ~btcreader ~dogewriter ~dogereader

# Place the scripts into the users' home directories and set their permissions.
cp btc_reset_writer.sh btc_run_bitcoind_writer.sh ~btcwriter; chown -R btcwriter:btcwriter ~btcwriter
cp btc_reset_reader.sh btc_run_bitcoind_reader.sh ~btcreader; chown -R btcreader:btcreader ~btcreader

cp doge_reset_writer.sh doge_run_dogecoind_writer.sh ~dogewriter; chown -R dogewriter:dogewriter ~dogewriter
cp doge_reset_reader.sh doge_run_dogecoind_reader.sh ~dogereader; chown -R dogereader:dogereader ~dogereader

echo "export CLI=bitcoin-cli" >> ~btcwriter/.profile
echo "export CLI=bitcoin-cli" >> ~btcreader/.profile
echo "export CLI=dogecoin-cli" >> ~dogewriter/.profile
echo "export CLI=dogecoin-cli" >> ~dogereader/.profile

wipe_output="alias wipe_output='rm -f \$HOME/output/log.txt \$HOME/output/lockfile \$HOME/output/bitclamp_sqlite.db \$HOME/output/partial/*'"
echo $wipe_output >> ~btcreader/.bashrc
echo $wipe_output >> ~dogereader/.bashrc

generate_blocks="alias generate_blocks='while [ 1 -eq 1 ]; do mempool=\`\$CLI getrawmempool\`; if [ \${#mempool} -ge 63 ]; then \$CLI generate 1 \$PUBKEY; else sleep 0.2; fi done'"
echo $generate_blocks >> ~btcwriter/.bashrc
echo $generate_blocks >> ~dogewriter/.bashrc


chmod 0700 ~btcwriter/*.sh ~btcreader/*.sh ~dogewriter/*.sh ~dogereader/*.sh 

# Initialize the BTC blockchain and start up the daemons.
su - btcwriter -c "~/btc_reset_writer.sh $PROJECT_BASE_DIR/BlockClient.py \$HOME/block_listeners.txt && ~/btc_run_bitcoind_writer.sh"
su - btcreader -c "mkdir -m 0700 \$HOME/output && ~/btc_reset_reader.sh $PROJECT_BASE_DIR/blockchain_watcher.py \$HOME/output \$HOME/output/bitclamp_sqlite.db && ~/btc_run_bitcoind_reader.sh"

# Wait for the service to start
num_blocks=`su - btcreader -c "bitcoin-cli getblockcount 2>&1"`
while [[ $num_blocks != "0" ]]; do
  sleep 0.25
  num_blocks=`su - btcreader -c "bitcoin-cli getblockcount 2>&1"`
done

# Determine if we're using Bitcoin Classic or Bitcoin Core.
version=`bitcoin-cli --version`
pubkey_master=
pubkey_watcher=
if [[ $version == *Classic* ]]; then
  echo "Found Bitcoin Classic."

  # Bitcoin Classic requires the raw public key when doing CPU mining.  So we get retrieve that here.

  address=`su - btcwriter -c "bitcoin-cli getaccountaddress \"\""`
  pubkey_master=`su - btcwriter -c "bitcoin-cli validateaddress $address | grep pubkey | cut -d\" \" -f4"`

  # Cut off the first and last two characters.
  pubkey_master=${pubkey_master:1:-2}

  address=`su - btcreader -c "bitcoin-cli getaccountaddress \"\""`
  pubkey_watcher=`su - btcreader -c "bitcoin-cli validateaddress $address | grep pubkey | cut -d\" \" -f4"`

  # Cut off the first and last two characters.
  pubkey_watcher=${pubkey_watcher:1:-2}

  echo "export PUBKEY=$pubkey_master" >> ~btcwriter/.profile
  echo "export PUBKEY=$pubkey_watcher" >> ~btcreader/.profile
else
  echo "Found Bitcoin Core."
fi

sleep 1

echo "Creating 101 initial blocks from writer..."
su - btcwriter -c "bitcoin-cli generate 101 $pubkey_master > /dev/null"

# Wait until the reader syncs all the blocks from the master.
echo "Synchronizing reader..."
synced_block_count=0
while [[ $synced_block_count < 101 ]]; do
  sleep 1
  synced_block_count=`su - btcreader -c "bitcoin-cli getblockcount"`
done


# Now that the chain is synced, generate blocks from the reader.  Ensure that it has at least 202 blocks.
echo "Creating another 101 blocks from reader..."
synced_block_count=0
while [[ $synced_block_count < 202 ]]; do
  su - btcreader -c "bitcoin-cli generate 101 $pubkey_watcher > /dev/null"
  sleep 1
  synced_block_count=`su - btcreader -c "bitcoin-cli getblockcount"`
done

# For good measure, wait until the master syncs at least 202 blocks.
echo "Synchronizing writer..."
synced_block_count=0
while [[ $synced_block_count < 202 ]]; do
  sleep 1
  synced_block_count=`su - btcwriter -c "bitcoin-cli getblockcount"`
done

echo
echo "Done initializing BTC network!"
echo
echo


# Initialize the DOGE blockchain and start up the daemons.
su - dogewriter -c "~/doge_reset_writer.sh $PROJECT_BASE_DIR/BlockClient.py \$HOME/block_listeners.txt && ~/doge_run_dogecoind_writer.sh"
su - dogereader -c "mkdir -m 0700 \$HOME/output && ~/doge_reset_reader.sh $PROJECT_BASE_DIR/blockchain_watcher.py \$HOME/output \$HOME/output/bitclamp_sqlite.db && ~/doge_run_dogecoind_reader.sh"


# Wait for the service to start
num_blocks=`su - dogereader -c "dogecoin-cli getblockcount 2>&1"`
while [[ $num_blocks != "0" ]]; do
  sleep 0.25
  num_blocks=`su - dogereader -c "dogecoin-cli getblockcount 2>&1"`
done

echo "Creating 101 initial blocks from writer..."
su - dogewriter -c "dogecoin-cli generate 101 > /dev/null"

# Wait until the watcher syncs all the blocks from the writer.
echo "Synchronizing reader..."
synced_block_count=0
while [[ $synced_block_count < 101 ]]; do
  sleep 1
  synced_block_count=`su - dogereader -c "dogecoin-cli getblockcount"`
done

# Now that the chain is synced, generate blocks from the reader.  Ensure that it has at least 202 blocks.
echo "Creating another 101 blocks from reader..."
su - dogereader -c "dogecoin-cli generate 101 > /dev/null"

synced_block_count=0
while [[ $synced_block_count < 202 ]]; do
  sleep 1
  synced_block_count=`su - dogereader -c "dogecoin-cli getblockcount"`
done

# For good measure, wait until the writer syncs at least 202 blocks.
echo "Synchronizing writer..."
synced_block_count=0
while [[ $synced_block_count < 202 ]]; do
  sleep 1
  synced_block_count=`su - dogewriter -c "dogecoin-cli getblockcount"`
done

echo
echo "Done initializing DOGE network!"
echo
echo


# GnuPG is noisy upon first invokation (while creating initial database).  So we run it here and suppress the output.
su - btcwriter -c "gpg2 --fingerprint 2> /dev/null"
su - btcreader -c "gpg2 --fingerprint 2> /dev/null"
su - dogewriter -c "gpg2 --fingerprint 2> /dev/null"
su - dogereader -c "gpg2 --fingerprint 2> /dev/null"
