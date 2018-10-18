package main

import "github.com/floppypanda/passwordhashingservice/pwdhashservice"

func main() {
	server := pwdhashservice.NewPasswordHashingServer(":8080")
	server.StartServer()
}
