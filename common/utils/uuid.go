package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"unsafe"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/randv2"
)

func UnsafeRandRead(p []byte) {
	for len(p) > 0 {
		v := randv2.Uint64()
		if v == 0 {
			continue
		}
		i := copy(p, (*[8]byte)(unsafe.Pointer(&v))[:])
		p = p[i:]
	}
}

type unsafeRandReader struct{}

func (r *unsafeRandReader) Read(p []byte) (n int, err error) {
	UnsafeRandRead(p)
	return len(p), nil
}

var UnsafeRandReader = (*unsafeRandReader)(nil)

// NewUUIDV3 returns a UUID based on the MD5 hash of the namespace UUID and name.
func NewUUIDV3(ns uuid.UUID, name string) (u uuid.UUID) {
	h := md5.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	copy(u[:], h.Sum(make([]byte, 0, md5.Size)))

	u.SetVersion(uuid.V3)
	u.SetVariant(uuid.VariantRFC9562)
	return u
}

// NewUUIDV4 returns a new version 4 UUID.
//
// Version 4 UUIDs contain 122 bits of random data.
func NewUUIDV4() (u uuid.UUID) {
	UnsafeRandRead(u[:])
	u.SetVersion(uuid.V4)
	u.SetVariant(uuid.VariantRFC9562)
	return u
}

// NewUUIDV5 returns a UUID based on SHA-1 hash of the namespace UUID and name.
func NewUUIDV5(ns uuid.UUID, name string) (u uuid.UUID) {
	h := sha1.New()
	h.Write(ns[:])
	h.Write([]byte(name))
	copy(u[:], h.Sum(make([]byte, 0, sha1.Size)))

	u.SetVersion(uuid.V5)
	u.SetVariant(uuid.VariantRFC9562)
	return u
}

// UUIDMap https://github.com/XTLS/Xray-core/issues/158#issue-783294090
func UUIDMap(str string) uuid.UUID {
	u, err := uuid.FromString(str)
	if err != nil {
		return NewUUIDV5(uuid.Nil, str)
	}
	return u
}
