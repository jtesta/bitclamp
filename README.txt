IMPORTANT NOTE:  Bitclamp is currently in beta.  DO NOT publish anything of value until it reaches a stable release (approximately December 2016).  There is a 100% chance that content published before then will not be easily viewable or searchable due to upcoming changes to the data structures.

----

This tool publishes files into the blockchains of Bitcoin and Dogecoin.  While other methods to push data into the blockchain exist, this project is special because it is much more reasonable in terms of cost (transaction fees), allows for data to be searched, and has no size limits (though the larger a file is, the longer it will take to publish).

Refer to the SETUP.txt file for instructions on how to get going with publishing and/or retrieving files.  Once that is complete, here is how to publish a file:

   python3 bitclamp.py --chain=btc --file=SEKRUT_STUFF.pdf --change mhnd4a9CNE3TFDuMRMXVEGaYfkkCwAcFvv

In the above example, --chain specifies what blockchain to use ("btc" or "doge"), --file is the file to publish, --change specifies where any leftover coins are to be sent after publication is complete, and the --rpc* options describe where the RPC server is (i.e.: the bitcoind/dogecoind process).

   bitclamp.py will respond with an address and amount to send:

   $ python3 bitclamp.py --chain=btc --file=SEKRUT_STUFF.pdf --change mhnd4a9CNE3TFDuMRMXVEGaYfkkCwAcFvv
   Automatic detection of content type is: document
   To begin publication, send 0.00964845 BTC to 2MuVjWDrUpCGC4jAU12rhrCDeqEj5XDcuCQ

   Sending at least the amount shown to this address will cause the publication process to begin.  No further intervention is needed:

   Parsed all TXIDs in block in 0 seconds.
   Received funds.  Beginning publication...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...
   Sent data block was confirmed.  Sending next block...

   Publication complete!  Waiting for the transactions to surpass the confirmation threshold.  This phase is optional.



Currently, the only way to extract content from the blockchain is to run bitcoind/dogecoind and examine blocks in realtime.  Future versions of Bitclamp will allow the user to specify ranges to parse, along with searches based on filename, type, etc.

To monitor the BTC blockchain in realtime, run bitcoind with the following arguments (note that the sqlite3 database will be created if it does not already exist):

    bitcoind -daemon -listen=0 -txindex -blocknotify="python3 /path/to/bitclamp/blockchain_watcher.py btc /path/to/sqlite3_db /path/to/btc/output/directory/ /path/to/btc/output_log.txt %s -d"

To monitor the DOGE blockchain in realtime, run dogecoind with (note that the sqlite3 database will be created if it does not already exist):
    dogecoind -daemon -listen=0 -txindex -blocknotify="python3 /path/to/bitclamp/blockchain_watcher.py doge /path/to/sqlite3_db /path/to/doge/output/directory/ /path/to/doge/output_log.txt %s -d"

The servers will dump new files into /path/to/output/directory/.
