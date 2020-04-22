package interfaces

import (
	"github.com/google/gopacket/pfring"
	"github.com/pkg/errors"
)

// InitPFRing initializes PFRing on the interface defined in the config
func (iface *Interfaces) InitPFRing() (ring *pfring.Ring, err error) {
	ring, err = pfring.NewRing(iface.Config.IFace, 65536, pfring.FlagPromisc)
	if err != nil {
		return nil, errors.Wrap(err, "unable to crate new pf_ring onject")
	}

	// If there is a BPF fitler then apply it
	if iface.Config.BPFfilter != "" {
		if err = ring.SetBPFFilter(iface.Config.BPFfilter); err != nil {
			return nil, errors.Wrap(err, "unable to define BPF filter")
		}
	}

	err = ring.Enable()
	if err != nil { // Must do this!, or you don't get packets!
		return nil, errors.Wrap(err, "unable to enable pf_ring")
	}
	return ring, nil
}
