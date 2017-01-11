Bitclamp v0.9
Joe Testa <jtesta [shift-two] positronsecurity [daht] com>
Positron Security
http://www.positronsecurity.com/


This tool publishes files into the blockchains of Bitcoin and Dogecoin.  While
other methods to push data into the blockchain exist, this project is special
because it is much more reasonable in terms of cost (transaction fees), allows
for data to be searched, and has no size limits.

IMPORTANT NOTE:  Bitclamp is currently in beta.  DO NOT publish anything of
value until it reaches a stable release (approximately January 2017).  There is
a 100% chance that content published before then will not be easily viewable or
searchable due to upcoming changes to the data structures.

Refer to the SETUP.txt file for instructions on how to initialize the bitcoind/
dogecoind servers.


1. Publication of Content

1.1. Quick Example

Assuming bitcoind/dogecoind is not currently running, a quick example is:

    $ python3 bitclamp.py --daemon=spawn --chain=btc --file=SEKRUT_DOC.pdf --txfee=0.0003 --change=mwbsGwGwSmaw6xZPT2G2rxxR63ErR6tjdx

In the above example, --chain specifies what blockchain to use ("btc" or
"doge"), --file is the file to publish, --txfee is the transaction fee rate per
KB (see section 1.2), and --change specifies where any leftover coins are to be
sent after publication is complete.

   The program responds with:

Automatic detection of content type is: document
Automatically adding file extension '.lzma' to file name to reflect usage of lzma compression: SEKRUT_DOC.pdf.lzma
To begin publication, send 0.06506440 BTC to 2MzquEsJsunGKw5ffrYsMr1jmbAu9WyKGn2

   Just like it says, you must send the specified amount to the listed address
in order to begin publication.  Once it is received, the program will say:

Received funds.  Beginning publication...

   Now its just a waiting game.  Depending on how large SEKRUT_DOC.pdf is,
publication can take anywhere from minutes to years (yes, literally years...).
See section 1.4 on how to get an estimate on publication times.

   Eventually, publication will complete, and the program will say:

Publication complete!  Waiting for the transactions to surpass the confirmation threshold.  This phase is optional.
4 transactions awaiting full confirmation...
0 transactions awaiting full confirmation...
All transactions fully confirmed.


1.2. Transaction Fees

Transactions fees are necessary for transactions to be processed.
Interestingly, fees are calculated with respect to the number of kilobytes a
transaction takes, and not based on the amount of coins being sent.  Senders
of funds choose the rate they wish to use.  A high rate will result in quick
confirmation, and a below-average rate causes transactions to be ignored for
a while.

The fee rate is determined by the open market at any given time.  As such, it
fluctuates based on current activity.  At the time of this writing, the
Dogecoin network does not experience high volume of transactions; its fee rate
appears to be very stable at 1 DOGE per KB (this is extremely cheap!).  The
Bitcoin network, however, has a very high volume, yielding high transaction
fees.

You can estimate the fee rate you should use in two ways:

   * By asking your local bitcoind node with "bitcoin-cli estimatefee N", where
        N is a number from 1 to 20 (omit this number to see the documentation
        on the estimatefee function).

   * By examining the current average fee rate.  The following websites can
     tell you this:
        - https://www.blocktrail.com/BTC
        - https://live.blockcypher.com/btc/
        - https://chain.so/

The higher the rate you use, the quicker your publication will complete.
However, it will obviously cost more (possibly a LOT more).  Choosing a lower
rate will save money, but will increase the amount of time required to finish.
This is a tradeoff decision you need to make on your own.

Be aware that the fee rate is somewhat cyclical.  There are peak times of
transaction volume, and times of low volume.  If the rate during peak times is,
say, 0.0003, and the rate during low volume is 0.0002, then using a rate in
between (0.00025) will strike a balance between publication time and cost.
Your transactions will be ignored when the market demands a higher rate, but
will be processed easily during low-volume times.


1.3. Daemon Existing Mode

The quick example in section 1.1 used "--daemon=spawn", which tells Bitclamp
that bitcoind/dogecoind should be spawned for publication, then shut down
when complete.  If you'd like for bitcoind/dogecoind to remain available
independently of the publication, you can run the daemon in "existing" mode
(this is also useful if you'd like to publish multiple files simultaneously):

    $ bitcoind -daemon -txindex -blocknotify="python3 /path/to/BlockClient.py /path/to/block_listeners.txt"

/path/to/BlockClient.py is (obviously) the path to where BlockClient.py exists.
/path/to/block_listeners.txt is a path to an (initially) empty file.  Later,
you will fill this in with information once publication is begun.

Once the daemon is started, you can start the publication with:

---

    $ python3 bitclamp.py --daemon=existing --chain=btc --file=SEKRUT_DOC.pdf --txfee=0.0003 --change=mwbsGwGwSmaw6xZPT2G2rxxR63ErR6tjdx --regtest

--> BlockListener is now listening on port 4761.  Configure bitcoind to connect back to this port, and publication can begin.  In the file that its BlockClient parses, add the following on a line by itself:

	localhost 4761

Do this BEFORE you send the funds to the publication address!

Automatic detection of content type is: document
Automatically adding file extension '.lzma' to file name to reflect usage of lzma compression: SEKRUT_DOC.pdf.lzma
To begin publication, send 0.06506440 BTC to 2N2aNnkW1fZ8qDgfFta8cdU3mTegWiZf5du
Received funds.  Beginning publication...
Sending about 0.04330063 in change to mwbsGwGwSmaw6xZPT2G2rxxR63ErR6tjdx...

---

Now place "localhost 4761" in /path/to/block_listeners.txt (as set in the
bitcoind/dogecoind argument, above).  Then send coins to the specified address
to begin publication.

   Note that multiple publications can be run using the same bitcoind/dogecoind
instance with this method by putting multiple lines in block_listeners.txt.


1.4. Estimation of Publication Cost & Time

Because publication cost and time can vary wildly based on file size and
specific blockchain used, the "--estimate" option allows the user to get an
estimate:

---

    $ python3 bitclamp.py --chain=btc --file=SEKRUT_DOC.pdf --estimate
Getting fee estimate from network...
Found fee estimate: 0.00022111
To publish SEKRUT_DOC.pdf (123.6 KB) on the BTC network with a transaction fee rate of 0.00022111, the amount needed to begin publishing is 0.04810583 BTC.  Of this figure, 0.04133116 will be lost to transaction fees, and 0.00050000 will be sent between transactions.  Based on the size of the file, an extra 15% is added to account for variability in the transaction sizes (larger files will have less added than smaller ones).  Because any and all unused funds are refunded upon completion, the true publication cost should be closer to the transaction fee cost (0.04133116).  With 1 concurrent transactions, and 5 outputs per transaction, publication will require at least 60 blocks, or at least 10 hours, 0 minutes.

Note that this is accurate under optimal network conditions.  Real-world conditions may vary greatly.

---

Note that, as of the time of this writing, the Bitcoin network is known to be
extremely slow at confirming transactions.  The Dogecoin network, however, is
quite fast.

The estimation feature supports the "--noutputs" and "--ntransactions" options
(see "Advanced Publication Features: Number of Outputs & Concurrent
Transactions" in section 1.4.2):

    $ python3 bitclamp.py --chain=doge --file=SEKRUT_DOC.pdf --estimate --txfee=1 --noutputs=7 --ntransactions=10
[...]
With 10 concurrent transactions, and 7 outputs per transaction, publication will require at least 10 blocks, or at least 10 minutes.
[...]


1.5. Advanced Publication Features

1.5.1. Custom Filenames and Descriptions

The filename of the publication can be changed or obscured with the "--name"
option.  In fact, the filename can be omitted entirely with "--name=''".

A custom description (up to 128 bytes) can be set with the "--description"
argument.  This field can be used later for searching content in the
blockchain (by default, the description field is blank).


1.5.2. Number of Outputs & Concurrent Transactions

By default, Bitclamp uses 5 outputs per transaction.  Because each output
allows 448 bytes to be published, this results in roughly 2240 bytes published
per transaction.  This can be changed through the "--noutputs" argument.

Also, Bitclamp transmits one transaction per block by default.  Multiple
transactions can be sent instead with the "--ntransactions" argument.

Before you get too excited, though, know that increasing these values will
likely *slow down* publication time on the Bitcoin network due to severe
congestion as of the time of this writing.

However, the Dogecoin network is quite under-utilized at the moment.  A VERY
significant speed boost can be obtained by setting "--ntransactions=10" or so.
In fact, 20 or 30 concurrent transactions may also be beneficial...


1.5.3. Plaintext Publishing

By default, publications are encrypted with a temporary, random key that is
divulged at the very end of the stream.  Hence, nothing is readable until the
entire file is fully published.

However, under certain circumstances, it may be desirable to publish the file
in plaintext so that its segments are immediately readable as publication
occurs.  In that case, use the "--no-crypto" option.

TODO: --no-hash


1.5.4. Deadman Switches

By default, files are encrypted with a random key before publication begins.
The key is normally released after the entire file is published.  However, you
can withhold the key in a separate key file to manually publish at a later time.

An external process can then be set to require you to check-in at regular
intervals.  If a check-in is missed, the key is automatically published.
Effectively, this becomes an "insurance policy" of sorts to protect yourself
from being arrested or killed.

See DEADMAN_SWITCH_README.txt for full documentation.


2. Explicit Extraction of Content

There are two ways of extracting content from the blockchain.  The blockchain
can be monitored in realtime and any discovered content can be written to an
output directory.  See the "Setup For Passive Monitoring Of New Content" in
SETUP.txt for information on how to set this up.

The second way is to use bitclamp_extracterizer.py to scan through part or all
of the blockchain.  To extract all content:

    $ python3 bitclamp_extracterizer.py --output=/tmp/btc_output
    $ ls -al /tmp/btc_output/
[...]
-rw-rw-r-- 1 btcwriter btcwriter   30133 Jan  9 10:29 omg.tar.bz2
-rw-rw-r-- 1 btcwriter btcwriter  126584 Jan  9 10:29 SEKRUT_DOC.pdf
-rw-rw-r-- 1 btcwriter btcwriter   55438 Jan  9 10:31 haha_im_using_the_internet.jpg

To extract all content between certain block numbers:

   $ python3 bitclamp_extracterizer.py --chain=doge --output=/tmp/doge_output --start-block=4000 --end-block=5000
   $ ls -al /tmp/doge_output/
[...]
-rw-rw-r-- 1 dogewriter dogewriter   24576 Jan  9 10:58 supercool.exe
-rw-rw-r-- 1 dogewriter dogewriter  102243 Jan  9 10:58 magic.zip

Its possible to filter based on content type.  To download all documents:

   $ python3 bitclamp_extracterizer.py --output=/tmp/btc_output2 --start-block=6000 --content-type document
   $ ls -al /tmp/btc_output2/
[...]
-rw-rw-r--  1 btcwriter btcwriter 126584 Jan  9 11:02 SEKRUT_DOC.pdf
-rw-rw-r--  1 btcwriter btcwriter 102955 Jan  9 11:03 roflcopter.docx

A filename filter can be applied as well:

   $ python3 bitclamp_extracterizer.py --output=/tmp/btc_output3 --start-block=6000 --filename=SEKRUT* --regtest
   $ ls -al /tmp/btc_output3/
[...]
-rw-rw-r--  1 btcwriter btcwriter 126584 Jan  9 11:14 SEKRUT_DOC.pdf
