// Copyright 2020 Jaume Martin

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package interfaces

import "errors"

const (
	IfaceOrFileNameIsNeededMsg   = "the interface or pcap file name is needed"
	IfaceValidationFaildMsg      = "the interface validation failed, because"
	PcapFileValidationFaildMsg   = "the pcap filename validation failed, because"
	InvalidIfaceMsg              = "the interface %s is not valid"
	InvalidFilenameMsg           = "the pcap filename %s is not valid"
	InterfaceConfigInitFailedMsg = "interfaces configutation failed, because"
	InterfacesInitMsg            = "interface intiated successfully"
	InterfacesListFailedMsg      = "unable to list system interfaces, because"
	PFRingInitFaildMsg           = "unable to crate new pf_ring object, because"
	LiveSnifferFaildMsg          = "unable to open pcap live sniffer, because"
	OfflineSnifferFaildMsg       = "unable to open pcap offline sniffer, because"
	SettingBPFFilterFailedMsg    = "unable to set the BPF filter, because"
	EnablePFRingFailedMsg        = "while enabling PFRing found"
	PFRingEnabledMsg             = "PFRing enabled successflly"
	PCAPEnabledMsg               = "PCAP sniffer enabled successflly"
	PCAPInitFailMsg              = "while initiating pcap got"
	PFRingInitFailMsg            = "while initiating pf_ring got"
	PFRingNotAvaliableMsg        = "PFRing is not avaliable. Falling down to PCAP sniffer"
	PcapFileNoExistMsg           = "the PCAP file provided does not exist"
	IfaceAndPcapFileMsg          = "Mole cannot handle sniffing from pcap file and an interface at the same time"
	PCAPPFRingMsg                = "PF_Ring cannot be usen when reading offline pcap traffic"
)

var (
	ErrIfaceOrFileNotProvided = errors.New(IfaceOrFileNameIsNeededMsg)
	ErrPcapFileNoExist        = errors.New(PcapFileNoExistMsg)
	ErrIfaceAndPcapFile       = errors.New(IfaceAndPcapFileMsg)
	ErrPCAPPFRing             = errors.New(PCAPPFRingMsg)
)
