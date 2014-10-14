package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"log"
	"time"
)

// Sniffer, is the struct that will let us read packets,
// this class can be layered and wrapped, for example -
// on top of Sniffer I can writer HttpSniffer - that will give me only http decoded packets
type Sniffer struct {
	handle *pcap.Handle

	// Storing the inactive handle so we clean it up, on close method
	inactiveHandle *pcap.InactiveHandle
}

// Creates a new sniffer from a PcapConfiguration,
// caller of this method should call "Close" as well, for example:
//          sniffer, err := NewSniffer(config)
//          defer sniffer.Close()
func NewSniffer(pcapConfiguration PcapConfiguraiton) (*Sniffer, error) {
	sniffer := Sniffer{}

	log.Println("Creating and configuring handler")
	inactiveHandle, err := CreateInactiveHandle(pcapConfiguration)
	if err != nil {
		return nil, err
	}
	sniffer.inactiveHandle = inactiveHandle

	log.Println("Activating handler")
	handle, err := inactiveHandle.Activate()
	if err != nil {
		return nil, err
	}
	sniffer.handle = handle

	log.Println("Setting bpf filter to", pcapConfiguration.BpfFilter)
	err = sniffer.handle.SetBPFFilter(pcapConfiguration.BpfFilter)
	if err != nil {
		return nil, err
	}

	return &sniffer, nil
}

// Create an inactive handle and configure it using the pcap configuration
func CreateInactiveHandle(pcapConfiguration PcapConfiguraiton) (*pcap.InactiveHandle, error) {
	inactiveHandle, err := pcap.NewInactiveHandle(pcapConfiguration.Device)
	if err != nil {
		return nil, err
	}

	err = inactiveHandle.SetSnapLen(pcapConfiguration.Sanplen)
	if err != nil {
		return nil, err
	}

	err = inactiveHandle.SetPromisc(pcapConfiguration.Promisc)
	if err != nil {
		return nil, err
	}

	// Making sure we get the packets as fast as they appear
	// see: http://godoc.org/code.google.com/p/gopacket/pcap#hdr-PCAP_Timeouts
	err = inactiveHandle.SetTimeout(time.Nanosecond)
	if err != nil {
		return nil, err
	}

	err = inactiveHandle.SetRFMon(pcapConfiguration.RFMon)
	if err != nil {
		return nil, err
	}

	return inactiveHandle, nil
}

// Clean up the inactive handle and closes the handle
func (sniffer *Sniffer) Close() {
	sniffer.inactiveHandle.CleanUp()
	sniffer.handle.Close()
}

// Read all the packets
func (sniffer *Sniffer) Packets() chan gopacket.Packet {
	packetSource := gopacket.NewPacketSource(sniffer.handle, sniffer.handle.LinkType())
	return packetSource.Packets()
}
