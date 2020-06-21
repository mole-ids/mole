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
package types

import "errors"

const (
	ConversionTypeMsg         = "type convertion is not allowed"
	WhileParsingCIDRMsg       = "building a IP node and while parsing CIDR address found"
	MixedFormatsNotAllowedMsg = "mixed formats are not allowed"
	RangeExceededMsg          = "port range can not contain more than one range splitter"
	InvalidPortNumberMsg      = "value %s is not valid port number"
	PortBaundsNotValidMsg     = "lower port cannot be higher or equal to the higher port in port range"
	UndefinedNodeMsg          = "undefined node"
)

var (
	ErrConversionType     = errors.New(ConversionTypeMsg)
	ErrMixedFormats       = errors.New(MixedFormatsNotAllowedMsg)
	ErrRangeExceeded      = errors.New(RangeExceededMsg)
	ErrPortBoundsNotValid = errors.New(PortBaundsNotValidMsg)
	ErrUndefinedNode      = errors.New(UndefinedNodeMsg)
)
