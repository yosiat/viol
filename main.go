package main

import (
	"fmt"
	"log"
)

// Currently this function is a playground...
// over the time hopefully it will be fully functional
func main() {
	config, err := ReadConfiguration()
	HandleError(err)

	log.Println("Creating new sniffer")
	sniffer, err := NewSniffer(config.Pcap)
	HandleError(err)
	defer sniffer.Close()

	log.Println("Starting to read packets")
	count := 0

	for _ = range sniffer.Packets() {
		count++
		fmt.Println("Got a packet", count)
	}

	fmt.Printf("%v", config)
}
