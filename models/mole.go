package models

type MolePacket struct {
	Proto    string
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Contents []byte
}
