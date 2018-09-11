package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime"
	"sync"
	"time"
)

const (
	numPollers = 2
)

type Dns struct {
	mu     sync.RWMutex
	dnsMap map[string][]string
}

var resolver *net.Resolver

func count() *Dns {
	return &Dns{
		dnsMap: make(map[string][]string),
	}
}

func fileRead(pathNetSeg string, debug bool, resolverSp *net.Resolver, resolverSt *net.Resolver) {
	wg := &sync.WaitGroup{}
	dnsSp, dnsSt := make(chan string, 1000), make(chan string, 1000)
	counterSp := count()
	counterSt := count()
	for i := 0; i < numPollers; i++ {
		wg.Add(2)
		go check(dnsSp, counterSp, wg, resolverSp)
		go check(dnsSt, counterSt, wg, resolverSt)
	}
	inFile, err := os.Open(pathNetSeg)
	if err != nil {
		errors.New("Can't open file with DNS strings")
	}
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		strLine := scanner.Text()
		dnsSp <- strLine
		dnsSt <- strLine
	}
	close(dnsSp)
	close(dnsSt)
	wg.Wait()
	compare(counterSp, counterSt, debug)
}

func check(str <-chan string, c *Dns, wg *sync.WaitGroup, resolver *net.Resolver) {
	for r := range str {
		addr, _ := resolver.LookupIPAddr(context.Background(), r)
		var s []string
		for _, ip := range addr {
			s = append(s, ip.String())
		}
		c.mu.Lock()
		c.dnsMap[r] = s
		c.mu.Unlock()
		runtime.Gosched()
	}
	wg.Done()
}

func compare(sp *Dns, st *Dns, debug bool) {
	for k, v := range st.dnsMap {
		if reflect.DeepEqual(sp.dnsMap[k], v) {
			continue
		} else if sp.dnsMap[k] == nil {
			fmt.Println("Alert: DNS spoof-server return an empty address", k)
			continue
		} else {
			fmt.Println("Alert: address", k, "not equal")
			if debug {
				fmt.Println("Spoofing server:", sp.dnsMap[k])
				fmt.Println("Standart server:", v)
				fmt.Println("-----------------------------------------")
			}
		}
	}
}

func setDNS(dns string, port string) *net.Resolver {
	resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Duration(9000)}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dns, port))
		},
	}
	return resolver
}

func main() {
	filePtr := flag.String("f", "", "Path to file with checklist file")
	dnsServSpPtr := flag.String("dsp", "", "DNS Server with spoofing")
	dnsServSpPortPtr := flag.String("psp", "53", "DNS Server port with spoofing")
	dnsServStPtr := flag.String("dst", "", "DNS Server for standart resolving")
	dnsServStPortPtr := flag.String("pst", "53", "DNS Server port for standart resolving")
	debugPtr := flag.Bool("d", false, "Debug mode with dns resolve 'A' record from standart and spoofing server")
	flag.Parse()
	var (
		resolverSp *net.Resolver
		resolverSt *net.Resolver
	)
	if *dnsServSpPtr != "" {
		resolverSp = setDNS(*dnsServSpPtr, *dnsServSpPortPtr)
	} else {
		resolverSp = net.DefaultResolver
	}

	if *dnsServStPtr != "" {
		resolverSt = setDNS(*dnsServStPtr, *dnsServStPortPtr)
	} else {
		resolverSt = net.DefaultResolver
	}
	fileRead(*filePtr, *debugPtr, resolverSp, resolverSt)
}
