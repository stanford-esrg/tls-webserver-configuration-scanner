package defaults

import (
	"github.com/zmap/zcrypto/tls"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func byteArrayEq(a, b []byte) bool {

	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

type CurveSlice []tls.CurveID
type CipherSlice []tls.CipherSuite
type VersionSlice []tls.TLSVersion
type StrSlice []string

func (s StrSlice) copy() StrSlice {
	return append(s[:0:0], s...)
}

func (s StrSlice) join(delim string) string {
	return strings.Join(s, delim)
}

func (s StrSlice) indexOf(element string) int {
	for i, v := range s {
		if element == v {
			return i
		}
	}
	return -1 //not found
}

func (s StrSlice) invPartialContains(str string) bool {
	for _, v := range s {
		if strings.Contains(str, v) {
			return true
		}
	}
	return false
}

func (s StrSlice) remove(r string) StrSlice {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func (s StrSlice) updatePresentedItems(selected_item string) StrSlice {

	indx := s.indexOf(selected_item)

	if indx != -1 {
		return s.remove(s[indx])
	}

	return StrSlice([]string{})
}

func (s VersionSlice) indexOf(element tls.TLSVersion) int {
	for i, v := range s {
		if element == v {
			return i
		}
	}
	return -1 //not found
}

func (s VersionSlice) remove(r tls.TLSVersion) VersionSlice {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func (s VersionSlice) copy() VersionSlice {
	return append(s[:0:0], s...)
}

func (s VersionSlice) updatePresentedItems(selected_item tls.TLSVersion) VersionSlice {

	indx := s.indexOf(selected_item)

	if indx != -1 {
		return s[indx+1:]
	}

	return VersionSlice([]tls.TLSVersion{})
}

func (s VersionSlice) getHighest() tls.TLSVersion {
	var max tls.TLSVersion
	for _, version := range s {
		if version > max {
			max = version
		}
	}

	return max
}

func (s CurveSlice) indexOf(element tls.CurveID) int {
	for i, v := range s {
		if element == v {
			return i
		}
	}
	return -1 //not found
}

func (s CurveSlice) remove(r tls.CurveID) CurveSlice {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func (s CurveSlice) copy() CurveSlice {
	return append(s[:0:0], s...)
}

func (s CurveSlice) ToIntStr() string {
	result := make([]string, len(s))
	for i, v := range s {
		result[i] = strconv.Itoa(int(v))
	}
	return strings.Join(result, ",")
}

// removes selected_item from presented_items slice
func (s CurveSlice) updatePresentedItems(selected_item tls.CurveID) CurveSlice {

	indx := s.indexOf(selected_item)

	if indx != -1 {
		return s.remove(s[indx])
	}

	return CurveSlice([]tls.CurveID{})
}

func (s CipherSlice) indexOf(element tls.CipherSuite) int {
	for i, v := range s {
		if element == v {
			return i
		}
	}
	return -1 //not found
}

func (s CipherSlice) remove(r tls.CipherSuite) CipherSlice {
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func (s CipherSlice) copy() CipherSlice {
	return append(s[:0:0], s...)
}

func (s CipherSlice) ToHexStr() string {
	result := make([]string, len(s))
	for i, v := range s {
		result[i] = v.HexString()
	}
	return strings.Join(result, ",")
}

func (s CipherSlice) toUIntArray() []uint16 {
	result := make([]uint16, len(s))
	for i, v := range s {
		result[i] = uint16(v)
	}
	return result
}

func (s CipherSlice) updatePresentedItems(selected_item tls.CipherSuite) CipherSlice {

	indx := s.indexOf(selected_item)

	if indx != -1 {
		return s.remove(s[indx])
	}

	return CipherSlice([]tls.CipherSuite{})
}

func (s CipherSlice) shuffle() CipherSlice {
	shuffled_ciphers := make([]tls.CipherSuite, len(s))

	r := rand.New(rand.NewSource(time.Now().Unix()))
	perm := r.Perm(len(s))

	for i, randIdx := range perm {
		shuffled_ciphers[i] = s[randIdx]
	}

	return shuffled_ciphers
}
