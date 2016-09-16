RPCPASS=[STUFF GOES HERE]
bitcoind -rpcuser=bitcoin -rpcpassword=$RPCPASS -rpcport=8888 -regtest -daemon -acceptnonstdtxn=0 -txindex
