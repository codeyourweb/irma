package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

// NetworkAnalysisRoutine dump network interfaces traffic
func NetworkAnalysisRoutine(bpffilter string, filename string, verbose bool) {
	// Check if WinPCAP installed
	if _, err := os.Stat(os.Getenv("SystemRoot") + "\\System32\\wpcap.dll"); os.IsNotExist(err) {
		logMessage(LOG_ERROR, "[ERROR] The network capture system requires the installation of WinPCAP on the workstation")
		return
	}

	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// Get a list of all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	// Creating pcap file
	_, err = os.Stat(filepath.Dir(filename))
	if os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(filename), 0600); err != nil {
			logMessage(LOG_ERROR, "[ERROR] Failed to create pcap file: ", err.Error())
			return
		}
	}

	f, err := os.Create(filename)
	if err != nil {
		logMessage(LOG_ERROR, "[ERROR] Failed to create pcap file: ", err.Error())
		return
	}
	defer f.Close()

	// listening for all interfaces
	for _, iface := range ifaces {
		if err := CaptureInterface(&iface, &devices, bpffilter, f, verbose); err != nil && verbose {
			logMessage(LOG_ERROR, "[ERROR]", err)
		}
	}
}

// CaptureInterface dump all packet on specified network interface
func CaptureInterface(iface *net.Interface, devices *[]pcap.Interface, bpffilter string, f *os.File, verbose bool) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				addr = &net.IPNet{
					IP:   ip4,
					Mask: ipnet.Mask[len(ipnet.Mask)-4:],
				}
				break
			}
		}
	}

	fmt.Printf("[INFO] Using network range %v for interface \"%v\"", addr, iface.Name)

	// Try to find a match between device and interface
	var deviceName string
	for _, d := range *devices {
		if strings.Contains(fmt.Sprint(d.Addresses), fmt.Sprint(addr.IP)) {
			deviceName = d.Name
		}
	}

	if deviceName == "" {
		return fmt.Errorf("Cannot find the corresponding device for the interface \"%v\"", iface.Name)
	}

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// BPF filter
	if len(bpffilter) > 0 {
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			return fmt.Errorf("BPF filter error: %s", err.Error())
		}
	}

	// Starting capture
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}

	return nil
}
