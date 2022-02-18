package tlshacks

import (
	"golang.org/x/crypto/cryptobyte"
)

type ExtensionData interface{}

type Extension struct {
	Type    uint16        `json:"type"`
	Name    string        `json:"name,omitempty"`
	Grease  bool          `json:"grease,omitempty"`
	Private bool          `json:"private,omitempty"`
	Data    ExtensionData `json:"data"`
}

type UnknownExtensionData struct {
	Raw []byte `json:"raw"`
}

func ParseUnknownExtensionData(data []byte) ExtensionData {
	return &UnknownExtensionData{
		Raw: data,
	}
}

type EmptyExtensionData struct {
	Raw   []byte `json:"raw"`
	Valid bool   `json:"valid"`
}

func ParseEmptyExtensionData(data []byte) ExtensionData {
	return &EmptyExtensionData{
		Raw:   data,
		Valid: len(data) == 0,
	}
}

// server_name - RFC 6066, Section 3
type ServerNameData struct {
	Raw      []byte `json:"raw"`
	Valid    bool   `json:"valid"`
	HostName string `json:"host_name"`
}

func ParseServerNameData(raw []byte) ExtensionData {
	sniData := &ServerNameData{Raw: raw}
	extData := cryptobyte.String(raw)
	var nameList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
		return sniData
	}
	for !nameList.Empty() {
		var nameType uint8
		if !nameList.ReadUint8(&nameType) {
			return sniData
		}
		var nameData cryptobyte.String
		if !nameList.ReadUint16LengthPrefixed(&nameData) || nameData.Empty() {
			return sniData
		}
		switch nameType {
		case 0:
			// host_name
			if sniData.HostName != "" {
				return sniData
			}
			sniData.HostName = string(nameData)
		}
	}
	if !extData.Empty() {
		return sniData
	}
	sniData.Valid = true
	return sniData
}

type ALPNData struct {
	Raw       []byte   `json:"raw"`
	Valid     bool     `json:"valid"`
	Protocols []string `json:"protocols"`
}

func ParseALPNData(raw []byte) ExtensionData {
	alpnData := &ALPNData{Raw: raw, Protocols: []string{}}
	extData := cryptobyte.String(raw)
	var nameList cryptobyte.String
	if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
		return alpnData
	}
	for !nameList.Empty() {
		var protocolName cryptobyte.String
		if !nameList.ReadUint8LengthPrefixed(&protocolName) || protocolName.Empty() {
			return alpnData
		}
		alpnData.Protocols = append(alpnData.Protocols, string(protocolName))
	}
	if !extData.Empty() {
		return alpnData
	}
	alpnData.Valid = true
	return alpnData
}

// RFC 8422
// TODO: provide info about groups beyond just the code (name, grease status, etc.)
type SupportedGroupsData struct {
	Raw    []byte   `json:"raw"`
	Valid  bool     `json:"valid"`
	Groups []uint16 `json:"groups"`
}

func ParseSupportedGroupsData(rawData []byte) ExtensionData {
	parsedData := &SupportedGroupsData{Raw: rawData, Groups: []uint16{}}
	data := cryptobyte.String(rawData)
	var groupList cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&groupList) || groupList.Empty() {
		return parsedData
	}
	for !groupList.Empty() {
		var groupCode uint16
		if !groupList.ReadUint16(&groupCode) {
			return parsedData
		}
		parsedData.Groups = append(parsedData.Groups, groupCode)
	}
	if !data.Empty() {
		return parsedData
	}
	parsedData.Valid = true
	return parsedData
}

// RFC 8422
type ECPointFormatsData struct {
	Raw     []byte   `json:"raw"`
	Valid   bool     `json:"valid"`
	Formats []uint16 `json:"formats"`
}

func ParseECPointFormatsData(rawData []byte) ExtensionData {
	parsedData := &ECPointFormatsData{Raw: rawData, Formats: []uint16{}}
	data := cryptobyte.String(rawData)
	var list cryptobyte.String
	if !data.ReadUint8LengthPrefixed(&list) || list.Empty() {
		return parsedData
	}
	for !list.Empty() {
		var code uint8
		if !list.ReadUint8(&code) {
			return parsedData
		}
		parsedData.Formats = append(parsedData.Formats, uint16(code))
	}
	if !data.Empty() {
		return parsedData
	}
	parsedData.Valid = true
	return parsedData
}

var extensionParsers = map[uint16]func([]byte) ExtensionData{
	0:  ParseServerNameData,
	10: ParseSupportedGroupsData,
	11: ParseECPointFormatsData,
	16: ParseALPNData,
	18: ParseEmptyExtensionData,
	22: ParseEmptyExtensionData,
	23: ParseEmptyExtensionData,
	49: ParseEmptyExtensionData,
}
