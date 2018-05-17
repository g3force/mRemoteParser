# mRemoteParser
Parse mRemoteNG config files and connect to hosts via native SSH

## Build

```
go get github.com/g3force/mRemoteParser
```
or
```
go install
```

## Usage

The GO executable will parse a given config file and search for the entry that best matches a given search query. 
It will then output the full ssh command that can be used to perform the connection.

The shell script is a wrapper that passes the config file and search string to the parser and executes the resulting command.