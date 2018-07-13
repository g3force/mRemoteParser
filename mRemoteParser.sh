#!/bin/bash

debug=1

if [ ! -e "$MREMOTE_CONFIG_FILE" ]; then
    echo "Set location of config file with the MREMOTE_CONFIG_FILE environment variable"
    exit 1
fi

input="mRemoteParser -f $MREMOTE_CONFIG_FILE $@"
[[ $debug == 1 ]] && echo "Input: $input"
command="`$input`"
[[ $debug == 1 ]] && echo "Command: $command"
eval $command
