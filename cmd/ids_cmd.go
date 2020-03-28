package cmd

// this is cmd/ids_cmd.go

import (
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"github.com/hillu/go-yara"
	"github.com/jpalanco/mole/conf"
	"github.com/jpalanco/mole/models"
	"github.com/jpalanco/mole/pkg/yaramole"
	"github.com/k0kubun/pp"
	"github.com/spf13/cobra"
)

// IDSCommand will setup and return the IDS command
func IDSCommand() *cobra.Command {
	IDSCmd := cobra.Command{
		Use: "start",
		Run: run,
	}

	// this is where we will configure everything!
	IDSCmd.Flags().String("config", "", "An explicit config file to use")
	IDSCmd.Flags().String("iface", "", "Listen on interface")
	IDSCmd.Flags().String("rulesDir", "", "Yara Rules directory")
	IDSCmd.Flags().String("rulesIndex", "", "Yara Rules directory")
	IDSCmd.Flags().String("bpf", "", "BPF filter")

	return &IDSCmd
}

func run(cmd *cobra.Command, args []string) {
	var config *conf.Config
	var err error
	config, err = conf.LoadConfig(cmd)
	if err != nil {
		log.Fatal("Failed to load config: " + err.Error())
	}
	pp.Println(config)
	logger, err := conf.ConfigureLogging(config.LogConfig)
	if err != nil {
		log.Fatalf("unable to configure logger: %s", err.Error())
	}
	logger.Info("configuration loaded successfull")

	if uid := syscall.Getuid(); uid != 0 {
		logger.Fatal("you need to be root")
	}

	inet, err := net.Interfaces()
	if err != nil {
		logger.Fatal(err.Error())
	}

	if !validInterface(inet, config.IFace) {
		logger.Fatalf("interface %s is no valid", config.IFace)
	}

	ring, err := pfring.NewRing(config.IFace, 65536, pfring.FlagPromisc)
	if err != nil {
		logger.Fatal(err.Error())
	}

	if config.BPFfilter != "" {
		if err = ring.SetBPFFilter(config.BPFfilter); err != nil {
			logger.Fatal(err.Error())
		}
	}

	if err := ring.Enable(); err != nil { // Must do this!, or you get no packets!
		logger.Fatal(err.Error())
	}

	scanner, err := yaramole.GetYaraScanner(config)
	if err != nil {
		logger.Fatalf(err.Error())
	}

	packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
	for packet := range packetSource.Packets() {

		if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
			//log.Println("Unusable packet")
			continue
		}

		// FIXME: assemble packets

		var mp models.MolePacket
		if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
			data := packet.TransportLayer().(*layers.TCP)
			mp.Contents = data.Contents
		} else if packet.TransportLayer().LayerType() == layers.LayerTypeUDP {
			data := packet.TransportLayer().(*layers.UDP)
			mp.Contents = data.Contents
		} else {
			continue
		}

		res, err := scanner.ScanMem(mp.Contents)
		if err != nil {
			logger.Warnf(err.Error())
		} else {
			printMatches(res)
		}
		// TODO: Create logger like eve.json
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

func printMatches(m []yara.MatchRule) {
	if m != nil && len(m) > 0 {
		for _, match := range m {
			fmt.Printf("- [%s] %s ", match.Namespace, match.Rule)
		}
	} else {
		fmt.Println("no matches.")
	}
}
