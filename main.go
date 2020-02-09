// sudo go run main.go -iface=enp6s0

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"github.com/hillu/go-yara"
)

type MyPacket struct {
	Proto    string
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Contents []byte
}

func Usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])

	flag.PrintDefaults()
}

func main() {

	// TODO: print help
	// TODO: parse optional BPFFilter

	uid := syscall.Getuid()

	if uid != 0 {
		fmt.Println("You need to be root to run this app!")
		os.Exit(1)
	}

	l, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var ifacePtr *string
	ifacePtr = flag.String("iface", l[0].Name, "The network device interface")
	flag.Parse()
	Usage()
	fmt.Println("Listening:", *ifacePtr)

	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}

	f, err := os.Open("demo.yar")
	if err != nil {
		log.Fatalf("Could not open rule file %s: %s", "demo.yar", err)
	}
	err = c.AddFile(f, "namespace")
	f.Close()
	if err != nil {
		log.Fatalf("Could not parse rule file %s: %s", "demo.yar", err)
	}

	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}

	if ring, err := pfring.NewRing(*ifacePtr, 65536, pfring.FlagPromisc); err != nil {
		panic(err)
		/*} else if err := ring.SetBPFFilter("tcp and port 80"); err != nil { // optional
		panic(err)*/
	} else if err := ring.Enable(); err != nil { // Must do this!, or you get no packets!
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
		for packet := range packetSource.Packets() {

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
				//log.Println("Unusable packet")
				continue
			}

			// FIXME: assemble packets

			var mp MyPacket

			if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
				data := packet.TransportLayer().(*layers.TCP)
				mp.Contents = data.Contents
			} else if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
				data := packet.TransportLayer().(*layers.UDP)
				mp.Contents = data.Contents
			} else {
				continue
			}

			//fmt.Println(mp.Contents) // Do something with a packet here.

			m, err := r.ScanMem(mp.Contents, 0, 0)
			printMatches(m, err)

			// TODO: Create logger like eve.json

		}
	}

}

func printMatches(m []yara.MatchRule, err error) {
	if err == nil {
		if len(m) > 0 {
			for _, match := range m {
				log.Printf("- [%s] %s ", match.Namespace, match.Rule)
			}
		} else {
			//log.Print("no matches.")
		}
	} else {
		log.Printf("error: %s.", err)
	}
}
