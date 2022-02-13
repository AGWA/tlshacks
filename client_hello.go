package tlshacks

import (
	"golang.org/x/crypto/cryptobyte"
)

type ClientHelloInfo struct {
	ServerName string
	SCTs       bool
}

func UnmarshalClientHello(handshakeBytes []byte) *ClientHelloInfo {
	info := new(ClientHelloInfo)
	handshakeMessage := cryptobyte.String(handshakeBytes)

	var messageType uint8
	if !handshakeMessage.ReadUint8(&messageType) || messageType != 1 {
		return nil
	}

	var clientHello cryptobyte.String
	if !handshakeMessage.ReadUint24LengthPrefixed(&clientHello) || !handshakeMessage.Empty() {
		return nil
	}

	// legacy_version
	if !clientHello.Skip(2) {
		return nil
	}

	// random
	if !clientHello.Skip(32) {
		return nil
	}

	var sessionID cryptobyte.String
	if !clientHello.ReadUint8LengthPrefixed(&sessionID) {
		return nil
	}

	var cipherSuites cryptobyte.String
	if !clientHello.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil
	}

	var legacyCompressionMethods cryptobyte.String
	if !clientHello.ReadUint8LengthPrefixed(&legacyCompressionMethods) {
		return nil
	}

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

		switch extType {
		case 0:
			// server_name - RFC 6066, Section 3
			var nameList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&nameList) || nameList.Empty() {
				return nil
			}
			for !nameList.Empty() {
				var nameType uint8
				if !nameList.ReadUint8(&nameType) {
					return nil
				}
				var nameData cryptobyte.String
				if !nameList.ReadUint16LengthPrefixed(&nameData) || nameData.Empty() {
					return nil
				}
				switch nameType {
				case 0:
					// host_name
					if info.ServerName != "" {
						return nil
					}
					info.ServerName = string(nameData)
				}
			}
			if !extData.Empty() {
				return nil
			}
		case 18:
			// signed_certificate_timestamp - RFC 6962, Section 3.3.1
			info.SCTs = true
			if !extData.Empty() {
				return nil
			}
		}

	}

	if !clientHello.Empty() {
		return nil
	}

	return info
}
