# mRemoteParser
Parse mRemoteNG config files and connect to hosts via native SSH

## Requirements

 * Go (for parsing)
 * SSH executable on PATH
 * sshpass executable on PATH (for passing passwords to SSH)

## Installation

Use go-get to download, install and update the tool:
```bash
go get -u github.com/g3force/mRemoteParser
```

## Configuration

The mRemoteNG config file can be specified with the `MREMOTE_CONFIG_FILE` environment variable or with the `-f` option.

## Usage

```
# Connect to host
mRemoteParser my host to connect to

# List all connections
mRemoteParser -l
```

The GO executable will parse a given config file and search for the entry that best matches a given search query. 
It will then connect to this host via SSH.
