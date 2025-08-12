/*
 * Copyright (C) 2025 Opsmate, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Except as contained in this notice, the name(s) of the above copyright
 * holders shall not be used in advertising or otherwise to promote the
 * sale, use or other dealings in this Software without prior written
 * authorization
 */

// Package authrootstl contains functions for parsing Microsoft's authroot.stl file
package authrootstl

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type CTL struct {
	SequenceNumber big.Int
	EffectiveDate  time.Time
	CTLogsVersion  []int32
	CTLogs         [][]byte
}

func ParseAuthrootstl(der cryptobyte.String) (*CTL, error) {
	_, content, err := parsePKCS7(der)
	if err != nil {
		return nil, fmt.Errorf("error parsing PKCS#7: %w", err)
	}
	ctl, err := parseCTL(content)
	if err != nil {
		return nil, fmt.Errorf("error parsing CTL: %w", err)
	}
	return ctl, nil
}

func parsePKCS7(der cryptobyte.String) (asn1.ObjectIdentifier, []byte, error) {
	var sequence cryptobyte.String
	if !der.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("malformed SEQUENCE")
	}
	if !sequence.SkipASN1(cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return nil, nil, fmt.Errorf("malformed OBJECT IDENTIFIER")
	}
	if !sequence.ReadASN1(&sequence, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, nil, fmt.Errorf("malformed SEQUENCE 2")
	}
	if !sequence.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("malformed SEQUENCE 3")
	}
	if !sequence.SkipASN1(cryptobyte_asn1.INTEGER) {
		return nil, nil, fmt.Errorf("malformed INTEGER")
	}
	if !sequence.SkipASN1(cryptobyte_asn1.SET) {
		return nil, nil, fmt.Errorf("malformed SET")
	}
	if !sequence.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("malformed SEQUENCE 4")
	}
	var oid asn1.ObjectIdentifier
	if !sequence.ReadASN1ObjectIdentifier(&oid) {
		return nil, nil, fmt.Errorf("malformed content OBJECT IDENTIFIER")
	}
	if !sequence.ReadASN1(&sequence, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, nil, fmt.Errorf("malformed SEQUENCE 5")
	}
	var content cryptobyte.String
	var contentTag cryptobyte_asn1.Tag
	if !sequence.ReadAnyASN1Element(&content, &contentTag) {
		return nil, nil, fmt.Errorf("malformed content element")
	}
	return oid, content, nil
}

func parseCTL(der cryptobyte.String) (*CTL, error) {
	ctl := new(CTL)
	var sequence cryptobyte.String
	if !der.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("malformed SEQUENCE")
	} else if !der.Empty() {
		return nil, fmt.Errorf("trailing bytes after SEQUENCE")
	}
	if !sequence.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("malformed signers SEQUENCE")
	}
	if !sequence.ReadASN1Integer(&ctl.SequenceNumber) {
		return nil, fmt.Errorf("malformed sequence number INTEGER")
	}
	if !sequence.ReadASN1UTCTime(&ctl.EffectiveDate) {
		return nil, fmt.Errorf("malformed effective date UTCTIME")
	}
	if !sequence.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("malformed algorithm identifier SEQUENCE")
	}
	if !sequence.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("malformed entries SEQUENCE")
	}
	var extensions cryptobyte.String
	var hasExtensions bool
	if !sequence.ReadOptionalASN1(&extensions, &hasExtensions, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, fmt.Errorf("malformed extensions SEQUENCE")
	}
	if hasExtensions {
		if !extensions.ReadASN1(&extensions, cryptobyte_asn1.SEQUENCE) {
			return nil, fmt.Errorf("malformed inner extensions SEQUENCE")
		}
		for !extensions.Empty() {
			var extension cryptobyte.String
			if !extensions.ReadASN1(&extension, cryptobyte_asn1.SEQUENCE) {
				return nil, fmt.Errorf("malformed extension SEQUENCE")
			}
			var id asn1.ObjectIdentifier
			if !extension.ReadASN1ObjectIdentifier(&id) {
				return nil, fmt.Errorf("malformed extension OBJECT IDENTIFIER")
			}
			if !extension.SkipOptionalASN1(cryptobyte_asn1.BOOLEAN) {
				return nil, fmt.Errorf("malformed extension BOOLEAN")
			}
			var value cryptobyte.String
			if !extension.ReadASN1(&value, cryptobyte_asn1.OCTET_STRING) {
				return nil, fmt.Errorf("malformed extension OCTET STRING")
			}
			switch {
			case id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 52}):
				var err error
				ctl.CTLogsVersion, ctl.CTLogs, err = parseCTLogs(value)
				if err != nil {
					return nil, fmt.Errorf("error parsing CT logs extension: %w", err)
				}
			}
		}
	}

	return ctl, nil
}

func parseCTLogs(der cryptobyte.String) ([]int32, [][]byte, error) {
	var sequence cryptobyte.String
	if !der.ReadASN1(&sequence, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("malformed SEQUENCE")
	} else if !der.Empty() {
		return nil, nil, fmt.Errorf("trailing bytes after SEQUENCE")
	}
	var versionSequence cryptobyte.String
	if !sequence.ReadASN1(&versionSequence, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("malformed version SEQUENCE")
	}
	var version []int32
	for !versionSequence.Empty() {
		var i int32
		if !versionSequence.ReadASN1Integer(&i) {
			return nil, nil, fmt.Errorf("version SEQUENCE contains malformed INTEGER")
		}
		version = append(version, i)
	}
	var pubkeys [][]byte
	for !sequence.Empty() {
		var spki cryptobyte.String
		if !sequence.ReadASN1Element(&spki, cryptobyte_asn1.SEQUENCE) {
			return nil, nil, fmt.Errorf("malformed SPKI SEQUENCE")
		}
		pubkeys = append(pubkeys, []byte(spki))
	}
	return version, pubkeys, nil
}
