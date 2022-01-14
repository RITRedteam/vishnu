# Vishnu(The Hidden Backdoor)

Taken from the Trimurit, the triple deity of supreme divinity. Vishnu is known as "The Preserver". This program is a proof of concept code to test the idea of port-knocking in golang.

Most backdoors usually have port listening and they can be easily be found by doing a port scan on the machine. This backdoor acts like as a packet sniffer, hence the need of libpcap, and looks for the `secret ports` you defined. When these ports are noticed, it creates a bind shell on a random port for you to connect to. To detect the random port, you can run nmap to find the new port.

* Note: This backdoor is not perfect, this was written in one night and again, it was a PoC :)

# Technical Details
At the beginning of the file, there are some configurations that needs to be set. Like what interface you want to listen to and what type of filter you want.

With the use of `gopacket(link)` which is a wrapper around libpcap, the program is able to read every packets that comes through the specific network interface. With this PoC, it is looking for SYN packets(this can be changed to whatever), if it is not, the packets are ignored. If the packet is a SYN, it looks at the destination port. 

In order for the hidden port to be open, the sequence of destination ports have to match what's in the array. For example, if the secret ports are `80, 81, 82, 83`, you have to send SYN packets in exactly that way. `81, 80, 83, 82` would not work.

After the comparison is done and matches, a random port between 100 and 65535 will be open by using the program `inetd`. You can learn more about here(link). Basically, it's an easy way to listen for connection on certain ports and you can decide what user should run a service and what service you want to run. In my case, I use this `<port> stream tcp nowait root /bin/bash bash`. When connected on that port, you are presented with a root bash bind shell.

# How to compile and Use
targetInterface is the interface you want to be listening on. To be more district, you can also change the secretPorts to whatever you want.

```
var (
	targetInterface = "ens160"
	secretPorts = []int{1, 2, 3, 4}
)
```

To compile, you need libpcap. On linux, you can install by running `sudo apt install libpcap-dev`. Then you can run `go build src/vishnu.go` to generate a binary.

For the port opening, make sure you have `inetd` installed. If you are not sure, run `apt install openbsd-inetd`.

## Connectback Shell

You can optionally have the backdoor operate in connectback mode - where after successfully knocking a shell is sent back to the knocking IP on a predetermined port. 

Be careful doing this behind NAT as while knocking will work, the shell won't get back to you. You'll need to do port forwarding or listen for the shell on a public IP.

```
const (
	connectback = true
	connectbackPort = "8080"
)
```

# Potential future works
* Design it to work for multiple operation systems(https://haydz.github.io/2020/07/06/Go-Windows-NIC.html )
* Dynamic secret ports so they are predictable.

# Disclamers
The author is in no way responsible for any illegal use of this software. It is provided purely as an educational proof of concept. I am also not responsible for any damages or mishaps that may happen in the course of using this software. Use at your own risk.
