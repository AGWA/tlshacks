package tlshacks

import (
	"golang.org/x/crypto/cryptobyte"
	"encoding/json"
)

type ProtocolVersion uint16

func (v ProtocolVersion) Hi() uint8 {
	return uint8(v >> 8)
}

func (v ProtocolVersion) Lo() uint8 {
	return uint8(v)
}

func (v ProtocolVersion) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]uint8{v.Hi(), v.Lo()})
}

type CompressionMethod uint8

func (m CompressionMethod) MarshalJSON() ([]byte, error) {
	return json.Marshal(uint16(m))
	/*
	return json.Marshal(map[string]interface{}{
		"code": uint16(m),
	})
	*/
}

type ClientHelloInfo struct {
	Raw []byte `json:"raw"`

	Version            ProtocolVersion      `json:"version"`
	Random             []byte      `json:"random"`
	SessionID          []byte      `json:"session_id"`
	CipherSuites       []CipherSuite      `json:"cipher_suites"`
	CompressionMethods []CompressionMethod      `json:"compression_methods"`
	Extensions         []Extension `json:"extensions"`

	Info struct{
		ServerName *string      `json:"server_name"`
		SCTs       bool      `json:"scts"`
		Protocols  []string  `json:"protocols"`
	} `json:"info"`
}

func UnmarshalClientHello(handshakeBytes []byte) *ClientHelloInfo {
	info := &ClientHelloInfo{Raw: handshakeBytes}
	handshakeMessage := cryptobyte.String(handshakeBytes)

	var messageType uint8
	if !handshakeMessage.ReadUint8(&messageType) || messageType != 1 {
		return nil
	}

	var clientHello cryptobyte.String
	if !handshakeMessage.ReadUint24LengthPrefixed(&clientHello) || !handshakeMessage.Empty() {
		return nil
	}

	if !clientHello.ReadUint16((*uint16)(&info.Version)) {
		return nil
	}

	if !clientHello.ReadBytes(&info.Random, 32) {
		return nil
	}

	if !clientHello.ReadUint8LengthPrefixed((*cryptobyte.String)(&info.SessionID)) {
		return nil
	}

	var cipherSuites cryptobyte.String
	if !clientHello.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil
	}
	info.CipherSuites = []CipherSuite{}
	for !cipherSuites.Empty() {
		var suite uint16
		if !cipherSuites.ReadUint16(&suite) {
			return nil
		}
		info.CipherSuites = append(info.CipherSuites, MakeCipherSuite(suite))
	}

	var compressionMethods cryptobyte.String
	if !clientHello.ReadUint8LengthPrefixed(&compressionMethods) {
		return nil
	}
	info.CompressionMethods = []CompressionMethod{}
	for !compressionMethods.Empty() {
		var method uint8
		if !compressionMethods.ReadUint8(&method) {
			return nil
		}
		info.CompressionMethods = append(info.CompressionMethods, CompressionMethod(method))
	}

	info.Extensions = []Extension{}

	if clientHello.Empty() {
		return info
	}
	var extensions cryptobyte.String
	if !clientHello.ReadUint16LengthPrefixed(&extensions) {
		return nil
	}
	for !extensions.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extType) || !extensions.ReadUint16LengthPrefixed(&extData) {
			return nil
		}

		parseData := extensionParsers[extType]
		if parseData == nil {
			parseData = ParseUnknownExtensionData
		}
		data := parseData(extData)

		info.Extensions = append(info.Extensions, Extension{
			Type: extType,
			Name: Extensions[extType],
			Data: data,
		})

		switch extType {
		case 0:
			info.Info.ServerName = &data.(*ServerNameData).HostName
		case 16:
			info.Info.Protocols = data.(*ALPNData).Protocols
		case 18:
			info.Info.SCTs = true
		}

	}

	if !clientHello.Empty() {
		return nil
	}

	return info
}
