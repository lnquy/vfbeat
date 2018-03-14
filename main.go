package main

import (
	"fmt"
	"log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var (
	devName  string
	err      error
	handle   *pcap.Handle
	InetAddr string
)

type (
	vfDecoder struct {
	}
)

func (d *vfDecoder) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	return nil
}

// CanDecode returns the set of LayerTypes this DecodingLayer can
// decode.  For Layers that are also DecodingLayers, this will most
// often be that Layer's LayerType().
func (d *vfDecoder) CanDecode() gopacket.LayerClass {
	return nil
}

// NextLayerType returns the LayerType which should be used to decode
// the LayerPayload.
func (d *vfDecoder) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// LayerPayload is the set of bytes remaining to decode after a call to
// DecodeFromBytes.
func (d *vfDecoder) LayerPayload() []byte {
	return []byte{}
}

func main() {
	devName = "enp0s31f6"

	//var eth layers.Ethernet
	//var ip4 layers.IPv4
	//var ip6 layers.IPv6
	//var udp layers.UDP

	// Find all devices
	devices, devErr := pcap.FindAllDevs()
	if devErr != nil {
		log.Fatal(devErr)
	}

	// Print device information
	fmt.Println("Device found:")
	getDevice(devices)

	// // Create DNSQuery index
	// _, elErr = client.CreateIndex("dns_query").Do()
	// if elErr != nil {
	//     // Handle error
	//     panic(elErr)
	// }

	// Open device
	handle, err = pcap.OpenLive(devName, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "udp and port 53" // and src host " + InetAddr
	fmt.Println("    BPF Filter: ", filter)
	err := handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	//parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &udp)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}

	//decodedLayers := make([]gopacket.LayerType, 0, 10)
	//for {
	//	data, _, err := handle.ReadPacketData()
	//	if err != nil {
	//		fmt.Println("Error reading packet data: ", err)
	//		continue
	//	}
	//
	//	err = parser.DecodeLayers(data, &decodedLayers)
	//	for _, typ := range decodedLayers {
	//		switch typ {
	//		case layers.LayerTypeIPv4:
	//			fmt.Printf("IPv4: %s - %s", ip4.SrcIP.String(), ip4.DstIP.String())
	//		case layers.LayerTypeIPv6:
	//			fmt.Printf("IPv6: %s - %s", ip6.SrcIP.String(), ip6.DstIP.String())
	//		}
	//	}
	//
	//	if err != nil {
	//		fmt.Println("  Error encountered:", err)
	//	}
	//}
}

func getDevice(devices []pcap.Interface) {
	for _, device := range devices {
		for _, address := range device.Addresses {
			if device.Name == devName {
				fmt.Println("Name: ", device.Name)
				fmt.Println("Description: ", device.Description)
				fmt.Println("Devices addresses: ", device.Description)
				fmt.Println("- IP address: ", address.IP)
				fmt.Println("- Subnet mask: ", address.Netmask)
				InetAddr = address.IP.String()
				return
			}
		}
	}
}
