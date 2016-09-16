These are instructions on how to set up a developer environment in Linux:

  1. Install Ubuntu 14.04 (other versions should work, but are untested).

  2. Install Python3:

        # apt-get install python3


For Bitcoin:

  1. Install Bitcoin Classic: https://bitcoinclassic.com/

  2. Create two users named "btcmaster" and "btcwatcher":

        # useradd -m btcmaster && useradd -m btcwatcher

  3. Execute:

        # cp reset_master.sh run_bitcoind_master.sh ~btcmaster; chown -R btcmaster:btcmaster ~btcmaster
        # cp reset_watcher.sh run_bitcoind_watcher.sh ~btcwatcher; chown -R btcwatcher:btcwatcher ~btcwatcher
        # chmod 0700 ~btcmaster/*.sh ~btcwatcher/*.sh


For Dogecoin:

  TODO
