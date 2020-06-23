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
package models

import (
	"strconv"
	"time"

	"go.uber.org/zap/zapcore"
)

const MoleTimestampFormat = "2006-01-02T15:04:05.999999-0700"

type MoleTime struct{ time.Time }

func (t *MoleTime) UnmarshalJSON(b []byte) error {
	data, err := strconv.Unquote(string(b))
	if err != nil {
		return err
	}
	t.Time, err = time.Parse(MoleTimestampFormat, data)
	return err
}

func (t *MoleTime) MarshalJSON() ([]byte, error) {
	return []byte("\"" + t.Time.Format(MoleTimestampFormat) + "\""), nil
}

func (t *MoleTime) GetMoletime() string {
	return t.Time.Format(MoleTimestampFormat)
}

// EveEvent is the huge struct which can contain a parsed suricata eve.json
// log event.
type EveEvent struct {
	Timestamp *MoleTime `json:"timestamp"`
	EventType string    `json:"event_type"`
	InIface   string    `json:"in_iface,omitempty"`
	SrcIP     string    `json:"src_ip,omitempty"`
	SrcPort   int       `json:"src_port,omitempty"`
	DstIP     string    `json:"dest_ip,omitempty"`
	DstPort   int       `json:"dest_port,omitempty"`
	Proto     string    `json:"proto,omitempty"`
	AppProto  string    `json:"app_proto,omitempty"`

	Alert   AlertEvent `json:"alert,omitempty"`
	Matches MatchArray `json:"matches,omitempty"`
}

type AlertEvent struct {
	Name string   `json:"name,omitempty"`
	ID   string   `json:"id,omitempty"`
	Tags TagArray `json:"tags,omitempty"`
	Meta MetaMap  `json:"meta,omitempty"`
}

type MatchString struct {
	Name   string `json:"name,omitempty"`
	Base   uint64 `json:"base,omitempty"`
	Offset uint64 `json:"offset,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

type TagArray []string
type MetaMap map[string]interface{}
type MatchArray []MatchString

func (eve *EveEvent) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("timestamp", eve.Timestamp.GetMoletime())
	enc.AddString("event_type", eve.EventType)
	enc.AddString("in_iface", eve.InIface)
	enc.AddString("src_ip", eve.SrcIP)
	enc.AddInt("src_port", eve.SrcPort)
	enc.AddString("dst_ip", eve.DstIP)
	enc.AddInt("dst_port", eve.DstPort)
	enc.AddString("proto", eve.Proto)
	enc.AddObject("alert", eve.Alert)
	enc.AddArray("matches", eve.Matches)
	return nil
}

func (alert AlertEvent) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("name", alert.Name)
	enc.AddString("id", alert.ID)
	enc.AddArray("tags", alert.Tags)
	enc.AddObject("meta", alert.Meta)
	return nil
}

func (tags TagArray) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, t := range tags {
		enc.AppendString(t)
	}
	return nil
}

func (meta MetaMap) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, v := range meta {
		enc.AddString(k, v.(string))
	}
	return nil
}

func (ms MatchString) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("name", ms.Name)
	enc.AddBinary("data", ms.Data)
	enc.AddUint64("base", ms.Base)
	enc.AddUint64("offset", ms.Offset)
	return nil
}

func (ma MatchArray) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	for _, o := range ma {
		enc.AppendObject(o)
	}
	return nil
}
