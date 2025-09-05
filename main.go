package main

import (
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/pflag"
)

func getUsableIPsFromStrings(inputs []string) ([]net.IP, error) {
	var ips []net.IP
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if strings.Contains(input, "/") { // Input is a netmask
			subnetIPs, err := expandSubnet(input)
			if err != nil {
				return nil, err
			}
			ips = append(ips, subnetIPs...)
		} else {
			ip := net.ParseIP(input)
			if ip == nil {
				return nil, &net.AddrError{Err: "invalid IP address", Addr: input}
			}
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// Expand a CIDR subnet into individual IPs, skipping network/broadcast for IPv4.
func expandSubnet(cidr string) ([]net.IP, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	ip := ipnet.IP.Mask(ipnet.Mask)

	for ; ipnet.Contains(ip); incrementIP(ip) {
		ipCopy := append(net.IP(nil), ip...) // copy the current IP
		if shouldSkipIPv4Address(ipCopy, ipnet) {
			continue
		}
		ips = append(ips, ipCopy)
	}

	return ips, nil
}

// Check if an IPv4 address is network or broadcast address.
func shouldSkipIPv4Address(ip net.IP, ipnet *net.IPNet) bool {
	if ip.To4() == nil {
		return false // IPv6, don't skip
	}

	// Check if it's the network address
	if ip.Equal(ipnet.IP.Mask(ipnet.Mask)) {
		return true
	}

	// Check if it's the broadcast address
	broadcast := make(net.IP, len(ipnet.IP))
	for i := range ipnet.IP {
		broadcast[i] = ipnet.IP[i] | ^ipnet.Mask[i]
	}

	return ip.Equal(broadcast)
}

// incrementIP increments an IP address (IPv4 or IPv6).
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}

// Parse port lists from string
func parsePorts(portStr string) ([]int, error) {
	var ports []int
	portStr = strings.TrimSpace(portStr)
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range: %s", portStr)
		}
		start, err1 := strconv.Atoi(parts[0])
		end, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
			return nil, fmt.Errorf("invalid port range: %s", portStr)
		}
		for p := start; p <= end; p++ {
			ports = append(ports, p)
		}
	} else {
		for _, p := range strings.Split(portStr, ",") {
			port, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port: %s", p)
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

// Scanning logic

type scanJob struct {
	target net.IP
	port   int
}

type scanJobResult struct {
	target net.IP
	port   int
	open   bool
}

func worker(jobs <-chan scanJob, results chan<- scanJobResult,
	wg *sync.WaitGroup, timeout time.Duration, maxRetries int) {

	for job := range jobs {
		var open bool
		for attempt := 0; attempt < maxRetries; attempt++ {
			conn, err := net.DialTimeout(
				"tcp",
				net.JoinHostPort(job.target.String(), strconv.Itoa(job.port)),
				timeout,
			)
			if err == nil {
				open = true
				conn.Close()
				break
			}
		}
		results <- scanJobResult{target: job.target, port: job.port, open: open}
		wg.Done()
	}
}

func run(targets []net.IP, ports []int,
	timeout time.Duration, workers int, maxRetries int, debug bool) []scanJobResult {
	jobs := make(chan scanJob, workers)
	results := make(chan scanJobResult, workers)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workers; i++ {
		go worker(jobs, results, &wg, timeout, maxRetries)
	}

	// Feed jobs
	go func() {
		for _, ip := range targets {
			for _, port := range ports {
				wg.Add(1)
				jobs <- scanJob{target: ip, port: port}
			}
		}
		wg.Wait()
		close(results)
	}()

	// Collect results
	var output []scanJobResult
	for result := range results {
		output = append(output, result)
		if debug && result.open {
			fmt.Printf("Open %s:%d\n", result.target, result.port)
		}
	}
	return output
}

func nmapScan(host string, ports []int, nmapArgs *string) (string, error) {
	portArgs := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]")
	args := []string{host, "-p", portArgs}

	if *nmapArgs != "" {
		args = append(args, strings.Fields(*nmapArgs)...)
	}

	cmd := exec.Command("nmap", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("[!] nmap error for %s: %v", host, err)
	}
	return string(output), nil
}

func main() {
	// Parse arguments
	addresses := pflag.StringP("addresses", "a", "", "Comma-separated list of addresses or CIDR ranges to scan")
	batchSize := pflag.IntP("batch-size", "b", 3000, "The batch size for port scanning")
	maxRetries := pflag.IntP("retries", "r", 1, "Number of retries for each port scan")
	portList := pflag.StringP("ports", "p", "1-65535", "A port range (e.g., 1-1000) or a list of comma separated ports (e.g., 22,80,443) to scan")
	debug := pflag.BoolP("debug", "d", false, "Enable debug output")
	timeout := pflag.IntP("timeout", "t", 1, "Timeout for each port scan")
	runNmap := pflag.BoolP("nmap", "n", false, "Run nmap on hosts with open ports")
	nmapArgs := pflag.StringP("nmapargs", "N", "", "Additional arguments for nmap (e.g., \"-sV\")")

	pflag.Parse()

	if *addresses == "" {
		pflag.Usage()
		return
	}

	ips, err := getUsableIPsFromStrings(strings.Split(*addresses, ","))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	ports, err := parsePorts(*portList)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if *runNmap {
		_, err := exec.LookPath("nmap")
		if err != nil {
			fmt.Println("Error: nmap not found in PATH. Please install nmap to use this feature")
			return
		}

	}

	portScanOutput := run(ips, ports, time.Duration(*timeout)*time.Second, *batchSize, *maxRetries, *debug)

	// Aggregate and print results
	ipPortMap := make(map[string][]int)
	for _, jobRes := range portScanOutput {
		ip := jobRes.target.String()
		if jobRes.open {
			ipPortMap[ip] = append(ipPortMap[ip], jobRes.port)
		}
	}

	for host, ports := range ipPortMap {
		sort.Ints(ports) // Sort ports
		fmt.Printf("%s -> %s\n", host, strings.Join(strings.Fields(fmt.Sprint(ports)), ","))
	}

	// Run nmap if required
	if *runNmap {
		for host, ports := range ipPortMap {
			output, err := nmapScan(host, ports, nmapArgs)
			if err != nil {
				fmt.Println("Error:", err)
				continue
			}
			fmt.Println(output)
		}
	}
}
