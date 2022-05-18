// Copyright (C) 2022 Andrew Ayer
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

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
