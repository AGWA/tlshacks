package tlshacks

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strconv"
)

func JA3String(hello *ClientHelloInfo) string {
	var (
		ciphers      string
		extensions   string
		groups       string
		pointFormats string
	)

	for _, cipher := range hello.CipherSuites {
		if !cipher.Grease {
			if len(ciphers) > 0 {
				ciphers += "-"
			}
			ciphers += strconv.FormatUint(uint64(cipher.CodeUint16()), 10)
		}
	}

	for _, ext := range hello.Extensions {
		if !ext.Grease {
			if len(extensions) > 0 {
				extensions += "-"
			}
			extensions += strconv.FormatUint(uint64(ext.Type), 10)
		}
		if ext.Type == 10 {
			data := ext.Data.(*SupportedGroupsData)
			for _, g := range data.Groups {
				if (g & 0x0F0F) != 0x0A0A {
					if len(groups) > 0 {
						groups += "-"
					}
					groups += strconv.FormatUint(uint64(g), 10)
				}
			}
		} else if ext.Type == 11 {
			data := ext.Data.(*ECPointFormatsData)
			for _, f := range data.Formats {
				if len(pointFormats) > 0 {
					pointFormats += "-"
				}
				pointFormats += strconv.FormatUint(uint64(f), 10)
			}
		}
	}

	return fmt.Sprintf("%d,%s,%s,%s,%s", hello.Version, ciphers, extensions, groups, pointFormats)
}

func JA3Fingerprint(ja3string string) string {
	digest := md5.Sum([]byte(ja3string))
	return hex.EncodeToString(digest[:])
}
