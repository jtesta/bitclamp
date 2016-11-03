#!/bin/bash

function deleteuser() {
  # Kill all the user's processes.
  su - $1 -c "kill -9 -1"

  # Delete the user and its home directory.
  userdel -r $1 2> /dev/null
  X=`id $1 > /dev/null 2> /dev/null`
  if [[ $? == 0 ]]; then
    echo "Error: could not delete $1 user.  Ensure that no processes are running as this user and try again."
    exit 0
  fi
}

if [[ `whoami` != 'root' ]]; then
  echo "You must be root to run this."
  exit -1
fi

deleteuser 'btcwriter'
deleteuser 'btcreader'
deleteuser 'dogewriter'
deleteuser 'dogereader'
