# Grabbing dependency.
FROM golang:1.10

# Copying the local package files to the container's workspace.
ADD . /go/src/github.com/floppypanda/passwordhashingservice

# Building and installing.
RUN go install github.com/floppypanda/passwordhashingservice

# Setting container entry point.
ENTRYPOINT /go/bin/passwordhashingservice

# Exposing default port.
EXPOSE 8080
