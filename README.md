# Password Hashing Microservice
A password hashing microservice written in Go.

## Getting Started
The following instructions describe how to get this project up and running for development and testing purposes.

### Prerequisites
The Go tools must be installed in order to build this project. Instructions for installing the Go tools can be found at 
[Go Tools](https://golang.org/doc/install).  
These instructions assume that commands are being run on a Unix based operating system, but may only require minor changes for a Windows environment.

### Installation
The password hashing microservice executable can be built and installed in the project directory by running:
```
go build
```
Or it can be built and installed at $HOME/go/bin or $GOPATH/go/bin by running:
```
go install
```  
If the latter installation method is used, it is recommended that $GOPATH/go/bin be added to PATH.

## Execution
The password hashing microservice can be started by running the executable directly:
```
./passwordhashingservice &
```
Or by using the Go tools:
```
go run main.go &
```
The server will then listen for connections on port 8080, by default.

## Running Automated Tests
All tests can be run recursively within the project directory as follows:
```
go test -v ./...
```
Or by explicity specifying the pwdhashservice package:
```
go test -v pwdhashservice
```
