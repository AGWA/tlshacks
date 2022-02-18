package tlshacks

type CipherSuite struct {
	Code [2]uint8 `json:"code"`
	Name string   `json:"name,omitempty"`
}

func (c CipherSuite) CodeUint16() uint16 {
	return (uint16(c.Code[0]) << 8) | uint16(c.Code[1])
}

func MakeCipherSuite(code uint16) CipherSuite {
	hi := uint8(code >> 8)
	lo := uint8(code)

	return CipherSuite{
		Code: [2]uint8{hi, lo},
		Name: CipherSuites[code],
	}
}
