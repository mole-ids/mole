package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"github.com/hillu/go-yara"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

var (
	iface     string
	bpfFilter string
	rulesDir  string
	version   = false

	// VersionNumber application version
	VersionNumber = "v0.0.0"
	// AppName appliction name
	AppName = "Mole"
	// BuildDate application compilation date
	BuildDate = ""
	// BuildHash git commit hash
	BuildHash = ""
)

// MolePacket Mole internal network packet
type MolePacket struct {
	Proto    string
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Contents []byte
}

func init() {
	pflag.StringVar(&iface, "iface", iface, "Listen on interface")
	pflag.StringVar(&rulesDir, "rulesDir", rulesDir, "Yara Rules directory")
	pflag.StringVar(&bpfFilter, "bpf", bpfFilter, "BPF filter")
	pflag.BoolVar(&version, "version", version, "Print version")
	pflag.Parse()

	viper.SetConfigName("mole")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/etc/mole/")
	viper.AddConfigPath(".")

	viper.BindPFlags(pflag.CommandLine)

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %s \n", err.Error()))
	}

	if version {
		fmt.Printf("%s version %s\nBuild Date: %s\nBuild Hash: %s\n", AppName, VersionNumber, BuildDate, BuildHash)
		os.Exit(0)
	}

	if viper.GetString("iface") == "" {
		fmt.Printf("Interfice must be defined\n")
		os.Exit(0)
	}
}

func main() {
	var moleConfig Config

	err := viper.Unmarshal(&moleConfig)
	if err != nil {
		log.Fatalf("unable to decode into struct, %s", err.Error())
	}

	if uid := syscall.Getuid(); uid != 0 {
		fmt.Println("You need to be root to run this app!")
		os.Exit(1)
	}

	l, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	if !validInterface(l, iface) {
		fmt.Printf("Interface %s is no valid", iface)
		os.Exit(1)
	}

	fmt.Printf("Listening: %s\n", iface)

	yarac, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err.Error())
	}

	f, err := os.Open("demo.yar") // This will be replaced by Yara Rules loader
	if err != nil {
		log.Fatalf("Could not open rule file %s: %s", "demo.yar", err.Error())
	}
	defer f.Close()

	err = yarac.AddFile(f, "namespace")
	if err != nil {
		log.Fatalf("Could not parse rule file %s: %s", "demo.yar", err.Error())
	}

	rules, err := yarac.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err.Error())
	}

	if ring, err := pfring.NewRing(iface, 65536, pfring.FlagPromisc); err != nil {
		panic(err)
		/*} else if err := ring.SetBPFFilter("tcp and port 80"); err != nil { // optional
		panic(err)*/
	} else if err := ring.Enable(); err != nil { // Must do this!, or you get no packets!
		panic(err)
	} else {
		scan, err := yara.NewScanner(rules)
		scanner := scan.SetCallback(printMatches)

		packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
		for packet := range packetSource.Packets() {

			if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
				//log.Println("Unusable packet")
				continue
			}

			// FIXME: assemble packets

			var mp MolePacket
			if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
				data := packet.TransportLayer().(*layers.TCP)
				mp.Contents = data.Contents
			} else if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
				data := packet.TransportLayer().(*layers.UDP)
				mp.Contents = data.Contents
			} else {
				continue
			}

			_, err = scanner.ScanMem(mp.Contents)
			if err != nil {
				// Log error o recover from it
			}

			// TODO: Create logger like eve.json

		}
	}

}

func printMatches(m []yara.MatchRule) {
	if m != nil && len(m) > 0 {
		for _, match := range m {
			log.Printf("- [%s] %s ", match.Namespace, match.Rule)
		}
	} else {
		//log.Print("no matches.")
	}
}

func validInterface(list []net.Interface, iface string) bool {
	for _, l := range list {
		if l.Name == iface {
			return true
		}
	}
	return false
}
