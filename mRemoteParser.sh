#!/bin/bash

confFile=confCons.xml
command="`go run mRemoteParser.go -f $confFile $@`"
echo $command
$command
