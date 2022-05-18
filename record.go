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
	"io"
)

type recordHeader struct {
	contentType uint8
	length      uint16
}

func readRecordHeader(reader io.Reader) (recordHeader, error) {
	var buffer [5]byte
	if _, err := io.ReadFull(reader, buffer[:]); err != nil {
		return recordHeader{}, err
	}
	return recordHeader{
		contentType: buffer[0],
		length:      (uint16(buffer[3]) << 8) | uint16(buffer[4]),
	}, nil
}

type HandshakeReader struct {
	reader         io.Reader
	bytesRemaining int
}

func NewHandshakeReader(reader io.Reader) *HandshakeReader {
	return &HandshakeReader{reader: reader}
}

func (r *HandshakeReader) Read(p []byte) (int, error) {
	for r.bytesRemaining == 0 {
		header, err := readRecordHeader(r.reader)
		if err != nil {
			return 0, err
		}
		if header.contentType == 22 {
			r.bytesRemaining = int(header.length)
		} else {
			if _, err := io.CopyN(io.Discard, r.reader, int64(header.length)); err != nil {
				return 0, err
			}
		}
	}
	if len(p) > r.bytesRemaining {
		p = p[:r.bytesRemaining]
	}
	bytesRead, err := r.reader.Read(p)
	r.bytesRemaining -= bytesRead
	return bytesRead, err
}

func (reader *HandshakeReader) ReadMessage() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := (uint32(header[1]) << 16) | (uint32(header[2]) << 8) | uint32(header[3])
	message := make([]byte, len(header)+int(length))
	copy(message, header[:])
	if _, err := io.ReadFull(reader, message[len(header):]); err != nil {
		return nil, err
	}
	return message, nil
}
