package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// IPNetwork represents an IP network with methods for comparison and processing
type IPNetwork struct {
	IPNet *net.IPNet
}

// NewIPNetwork creates a new IPNetwork from a string
func NewIPNetwork(cidr string) (*IPNetwork, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return &IPNetwork{IPNet: ipnet}, nil
}

// String returns the string representation of the network
func (n *IPNetwork) String() string {
	return n.IPNet.String()
}

// NetworkAddress returns the network address
func (n *IPNetwork) NetworkAddress() net.IP {
	return n.IPNet.IP
}

// Prefixlen returns the prefix length
func (n *IPNetwork) Prefixlen() int {
	ones, _ := n.IPNet.Mask.Size()
	return ones
}

// BroadcastAddress returns the broadcast address
func (n *IPNetwork) BroadcastAddress() net.IP {
	ip := n.IPNet.IP.To4()
	if ip == nil {
		// IPv6 - for simplicity, we only implement IPv4
		return nil
	}
	
	mask := n.IPNet.Mask
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

// SubnetOf checks if the network is a subnet of another network
func (n *IPNetwork) SubnetOf(other *IPNetwork) bool {
	return other.IPNet.Contains(n.IPNet.IP) && n.Prefixlen() >= other.Prefixlen()
}

// SupernetOf checks if the network is a supernet of another network
func (n *IPNetwork) SupernetOf(other *IPNetwork) bool {
	return n.IPNet.Contains(other.IPNet.IP) && n.Prefixlen() <= other.Prefixlen()
}

// Supernet creates a supernet with a new prefix
func (n *IPNetwork) Supernet(newPrefix int) (*IPNetwork, error) {
	if newPrefix >= n.Prefixlen() {
		return nil, fmt.Errorf("new prefix must be smaller than current prefix")
	}
	
	ip := n.IPNet.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("only IPv4 supported")
	}
	
	newMask := net.CIDRMask(newPrefix, 32)
	newIP := make(net.IP, len(ip))
	copy(newIP, ip)
	
	// Zero out bits after the new prefix
	for i := 0; i < len(newIP); i++ {
		newIP[i] &= newMask[i]
	}
	
	return &IPNetwork{
		IPNet: &net.IPNet{
			IP:   newIP,
			Mask: newMask,
		},
	}, nil
}

// IPToInt converts IP to integer
func IPToInt(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// IntToIP converts integer to IP
func IntToIP(val uint32) net.IP {
	return net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
}

// AggressiveAggregate aggressively aggregates networks, combining them up to the specified prefix
func AggressiveAggregate(networks []*IPNetwork, maxPrefixlen int) []*IPNetwork {
	if len(networks) == 0 {
		return []*IPNetwork{}
	}
	
	// Group networks by first octet
	networksByFirstOctet := make(map[string][]*IPNetwork)
	for _, net := range networks {
		ipStr := net.NetworkAddress().String()
		firstOctet := strings.Split(ipStr, ".")[0]
		networksByFirstOctet[firstOctet] = append(networksByFirstOctet[firstOctet], net)
	}
	
	var aggregated []*IPNetwork
	
	for firstOctet, octetNetworks := range networksByFirstOctet {
		// Sort networks in the group
		sort.Slice(octetNetworks, func(i, j int) bool {
			return IPToInt(octetNetworks[i].NetworkAddress()) < IPToInt(octetNetworks[j].NetworkAddress())
		})
		
		// Try to create supernets for each second octet
		networksBySecondOctet := make(map[string][]*IPNetwork)
		for _, net := range octetNetworks {
			ipStr := net.NetworkAddress().String()
			secondOctet := strings.Split(ipStr, ".")[1]
			networksBySecondOctet[secondOctet] = append(networksBySecondOctet[secondOctet], net)
		}
		
		// For each second octet, create aggregated networks
		for secondOctet, secondOctetNets := range networksBySecondOctet {
			if len(secondOctetNets) > 3 { // If there are multiple networks in the same second octet
				// Try to create /16
				supernet, err := NewIPNetwork(fmt.Sprintf("%s.%s.0.0/16", firstOctet, secondOctet))
				if err == nil {
					// Check if this network covers all subnets
					coversAll := true
					for _, net := range secondOctetNets {
						if !net.SubnetOf(supernet) {
							coversAll = false
							break
						}
					}
					if coversAll {
						aggregated = append(aggregated, supernet)
						continue
					}
				}
			}
			
			// If /16 could not be created, use regular aggregation
			var currentGroup []*IPNetwork
			sort.Slice(secondOctetNets, func(i, j int) bool {
				return IPToInt(secondOctetNets[i].NetworkAddress()) < IPToInt(secondOctetNets[j].NetworkAddress())
			})
			
			for _, net := range secondOctetNets {
				if len(currentGroup) == 0 {
					currentGroup = append(currentGroup, net)
				} else {
					// Try to merge with the previous network
					lastNet := currentGroup[len(currentGroup)-1]
					
					// Try to create a supernet with a prefix not less than maxPrefixlen
					commonPrefix := min(lastNet.Prefixlen(), net.Prefixlen())
					merged := false
					
					for commonPrefix >= maxPrefixlen {
						supernet, err := lastNet.Supernet(commonPrefix - 1)
						if err == nil && supernet.SupernetOf(net) {
							currentGroup[len(currentGroup)-1] = supernet
							merged = true
							break
						}
						commonPrefix--
					}
					
					if !merged {
						currentGroup = append(currentGroup, net)
					}
				}
			}
			
			aggregated = append(aggregated, currentGroup...)
		}
	}
	
	return aggregated
}

// SmartAggregateBySecondOctet smart aggregation by second octet
func SmartAggregateBySecondOctet(networks []*IPNetwork) []*IPNetwork {
	if len(networks) == 0 {
		return []*IPNetwork{}
	}
	
	// Group by first two octets
	networksByPrefix := make(map[string][]*IPNetwork)
	for _, net := range networks {
		ipStr := net.NetworkAddress().String()
		parts := strings.Split(ipStr, ".")
		if len(parts) < 2 {
			continue
		}
		key := fmt.Sprintf("%s.%s", parts[0], parts[1])
		networksByPrefix[key] = append(networksByPrefix[key], net)
	}
	
	var aggregated []*IPNetwork
	
	for prefix, netList := range networksByPrefix {
		if len(netList) >= 5 { // If there are enough networks in this /16
			// Try to create /16
			supernet, err := NewIPNetwork(fmt.Sprintf("%s.0.0/16", prefix))
			if err == nil {
				// Check that all networks are indeed within this /16
				allInSupernet := true
				for _, net := range netList {
					if !net.SubnetOf(supernet) {
						allInSupernet = false
						break
					}
				}
				if allInSupernet {
					aggregated = append(aggregated, supernet)
					continue
				}
			}
		}
		
		// If /16 could not be created, use step-by-step aggregation
		sort.Slice(netList, func(i, j int) bool {
			return IPToInt(netList[i].NetworkAddress()) < IPToInt(netList[j].NetworkAddress())
		})
		
		// Try to aggregate step by step
		i := 0
		for i < len(netList) {
			current := netList[i]
			j := i + 1
			
			for j < len(netList) {
				// Try to find a common supernet
				commonNetworks := netList[i : j+1]
				
				// Find the minimum network that covers all current ones
				minIP := netList[i].NetworkAddress()
				maxIP := netList[i].BroadcastAddress()
				
				for _, net := range commonNetworks {
					if IPToInt(net.NetworkAddress()) < IPToInt(minIP) {
						minIP = net.NetworkAddress()
					}
					if IPToInt(net.BroadcastAddress()) > IPToInt(maxIP) {
						maxIP = net.BroadcastAddress()
					}
				}
				
				// Calculate the minimum prefix that covers the range
				rangeSize := IPToInt(maxIP) - IPToInt(minIP) + 1
				requiredPrefix := 32 - bitLength(rangeSize-1)
				if requiredPrefix < 16 {
					requiredPrefix = 16 // Not less than /16
				}
				
				if requiredPrefix <= 24 { // Acceptable size
					supernet, err := NewIPNetwork(fmt.Sprintf("%s/%d", minIP, requiredPrefix))
					if err == nil {
						allInSupernet := true
						for _, net := range commonNetworks {
							if !net.SubnetOf(supernet) {
								allInSupernet = false
								break
							}
						}
						if allInSupernet {
							current = supernet
							j++
							continue
						}
					}
				}
				break
			}
			
			aggregated = append(aggregated, current)
			i = j
		}
	}
	
	return aggregated
}

// ProcessNetworksInplace processes the file in-place
func ProcessNetworksInplace(inputFile string) error {
	// Create a temporary file for safe writing
	tempFile := inputFile + ".tmp"
	
	// Read all networks from the source file
	content, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}
	
	lines := strings.Split(string(content), "\n")
	var networks []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			networks = append(networks, line)
		}
	}
	
	// Parse networks and collect second octet
	var parsedNetworks []*IPNetwork
	var secondOctets []string
	
	for _, netStr := range networks {
		net, err := NewIPNetwork(netStr)
		if err != nil {
			fmt.Printf("Error parsing network %s: %v\n", netStr, err)
			continue
		}
		parsedNetworks = append(parsedNetworks, net)
		ipStr := net.NetworkAddress().String()
		parts := strings.Split(ipStr, ".")
		if len(parts) >= 2 {
			secondOctets = append(secondOctets, parts[1])
		}
	}
	
	// Count frequency of second octets
	octetCounter := make(map[string]int)
	for _, octet := range secondOctets {
		octetCounter[octet]++
	}
	
	// Find octets that appear more than 10 times
	var frequentOctets []string
	for octet, count := range octetCounter {
		if count > 10 {
			frequentOctets = append(frequentOctets, octet)
		}
	}
	fmt.Printf("Found octets with frequency > 10: %d\n", len(frequentOctets))
	
	// Split networks into two groups
	var frequentNetworks []*IPNetwork
	var otherNetworks []*IPNetwork
	
	for i, net := range parsedNetworks {
		if i < len(secondOctets) {
			octet := secondOctets[i]
			found := false
			for _, freqOctet := range frequentOctets {
				if octet == freqOctet {
					found = true
					break
				}
			}
			if found {
				frequentNetworks = append(frequentNetworks, net)
			} else {
				otherNetworks = append(otherNetworks, net)
			}
		}
	}
	
	fmt.Printf("Networks with frequent octets: %d\n", len(frequentNetworks))
	fmt.Printf("Remaining networks: %d\n", len(otherNetworks))
	
	// Aggressively aggregate networks with frequent octets
	fmt.Println("Aggressively aggregating networks...")
	
	// First pass: aggregation by second octet
	aggregated1 := SmartAggregateBySecondOctet(frequentNetworks)
	fmt.Printf("After first pass: %d networks\n", len(aggregated1))
	
	// Second pass: aggressive aggregation
	aggregatedFinal := AggressiveAggregate(aggregated1, 14)
	fmt.Printf("After second pass: %d networks\n", len(aggregatedFinal))
	
	// Combine all networks for final output
	var allNetworks []*IPNetwork
	allNetworks = append(allNetworks, aggregatedFinal...)
	allNetworks = append(allNetworks, otherNetworks...)
	
	// Sort the final list
	sort.Slice(allNetworks, func(i, j int) bool {
		ipI := IPToInt(allNetworks[i].NetworkAddress())
		ipJ := IPToInt(allNetworks[j].NetworkAddress())
		if ipI != ipJ {
			return ipI < ipJ
		}
		return allNetworks[i].Prefixlen() < allNetworks[j].Prefixlen()
	})
	
	// Write the result to a temporary file
	var outputLines []string
	for _, net := range allNetworks {
		outputLines = append(outputLines, net.String())
	}
	
	err = ioutil.WriteFile(tempFile, []byte(strings.Join(outputLines, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("error writing temporary file: %v", err)
	}
	
	// Replace the original file with the temporary one
	err = os.Rename(tempFile, inputFile)
	if err != nil {
		return fmt.Errorf("error replacing file: %v", err)
	}
	
	// Statistics
	fmt.Printf("\nResult:\n")
	fmt.Printf("Original number of networks: %d\n", len(parsedNetworks))
	fmt.Printf("Final number of networks: %d\n", len(allNetworks))
	fmt.Printf("Reduction: %d networks\n", len(parsedNetworks)-len(allNetworks))
	efficiency := (1 - float64(len(allNetworks))/float64(len(parsedNetworks))) * 100
	fmt.Printf("Efficiency: %.1f%%\n", efficiency)
	
	// Show the largest aggregated supernets
	fmt.Printf("\nLargest aggregated supernets:\n")
	var largeNets []*IPNetwork
	for _, net := range aggregatedFinal {
		if net.Prefixlen() <= 20 {
			largeNets = append(largeNets, net)
		}
	}
	
	sort.Slice(largeNets, func(i, j int) bool {
		return largeNets[i].Prefixlen() < largeNets[j].Prefixlen()
	})
	
	for i := 0; i < len(largeNets) && i < 10; i++ {
		net := largeNets[i]
		addresses := 1 << (32 - net.Prefixlen())
		fmt.Printf("  %s (covers ~%s addresses)\n", net, formatNumber(addresses))
	}
	
	return nil
}

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func bitLength(n uint32) int {
	if n == 0 {
		return 0
	}
	return 32 - len(strconv.FormatUint(uint64(n), 2)) + 1
}

func formatNumber(n int) string {
	s := strconv.Itoa(n)
	var result string
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result += ","
		}
		result += string(c)
	}
	return result
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./netagg <filename>")
		fmt.Println("Example: ./netagg networks.txt")
		os.Exit(1)
	}
	
	inputFile := os.Args[1]
	
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Printf("Error: file '%s' not found\n", inputFile)
		os.Exit(1)
	}
	
	fmt.Printf("Processing file: %s\n", inputFile)
	err := ProcessNetworksInplace(inputFile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\nFile '%s' successfully updated!\n", inputFile)
}