package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/aeden/traceroute"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func getDefIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

var (
	timeout   = 30 * time.Second
	ph        *pcap.Handle
	msSubnets = []string{
		"13.107.8.0/24",
		"13.107.64.0/18",
		"52.112.0.0/14",
		"104.44.195.0/24",
		"104.44.200.0/23",
	}

	measurePeriod = 60 * time.Second
	skypeCalls    map[string]time.Time
)

func isMSIP(i net.IP) bool {

	for _, subnet := range msSubnets {
		_, network, _ := net.ParseCIDR(subnet)
		if network.Contains(i) {
			return true
		}
	}
	return false
}

func doTrace(i net.IP, port int) {
	var traceOpts traceroute.TracerouteOptions
	msIPPort := fmt.Sprintf("%s:%d", i.String(), port)

	traceOpts.SetPort(port)
	traceOpts.SetTimeoutMs(300)
	traceOpts.SetMaxHops(20)

	trace, err := traceroute.Traceroute(i.String(), &traceOpts)
	if err != nil {
		log.Fatal(err)
	}
	for i := 0; i < len(trace.Hops); i++ {
		hop := trace.Hops[i]
		hopIP := net.IPv4(hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
		hopLatency := float64(hop.ElapsedTime) / 1000000.0
		log.Printf("[%s]%d %s(%s): %f ms \n", msIPPort, hop.TTL, hopIP.String(), hop.Host, hopLatency)
	}
}

func main() {
	origuser := os.Getenv("SUDO_USER")
	skypeCalls = make(map[string]time.Time)
	if origuser == "" || os.Geteuid() != 0 {
		log.Fatal("Needs root access. Please run this through sudo.")
	}

	log.Printf("Username: %s\n", origuser)

	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	defINT := ""
	defIP := getDefIP()
	log.Printf("Default route IP: %s\n", defIP.String())

	for _, device := range devices {
		for _, address := range device.Addresses {

			if address.IP.String() == defIP.String() {
				defINT = device.Name
			}
		}
	}

	log.Printf("Default interface: %s\n", defINT)
	ph, err = pcap.OpenLive(defINT, 512, false, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer ph.Close()

	// SfB uses udp ports 50000-59999 for normal calls
	filter := "udp and src portrange 50000-59999 and dst portrange 50000-59999"
	err = ph.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(ph, ph.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			udp, _ := udpLayer.(*layers.UDP)
			if isMSIP(ip.DstIP) {
				msIPPort := fmt.Sprintf("%s:%d", ip.DstIP, udp.DstPort)
				if t, ok := skypeCalls[msIPPort]; ok {
					if time.Since(t) > measurePeriod {
						log.Printf("Re-measuring %s \n", msIPPort)
						go doTrace(ip.DstIP, int(udp.DstPort))
						skypeCalls[msIPPort] = time.Now()
					}
				} else {
					log.Printf("New Skype call: %s\n", msIPPort)
					go doTrace(ip.DstIP, int(udp.DstPort))
					skypeCalls[msIPPort] = time.Now()
				}
			}
		}
	}

}
