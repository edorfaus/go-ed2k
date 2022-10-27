package ed2k

import (
	"hash"
	"testing"

	"golang.org/x/crypto/md4"
)

// chunkSize is the size of each chunk of the ed2k hash, in bytes.
const chunkSize = 9728000

// emptyMD4 is the MD4 hash of nothing, needed by SumRed in some cases.
var emptyMD4 = md4.New().Sum(nil)

type Ed2k struct {
	hashes []byte // md4 hashes of chunks
	chunk  hash.Hash
	size   int

	t *testing.T
}

func New() *Ed2k {
	return &Ed2k{
		chunk: md4.New(),
	}
}

func (h *Ed2k) setTest(t *testing.T) {
	h.t = t
}

func (h *Ed2k) Write(p []byte) (int, error) {
	// If we won't fill the current chunk, just write what we can
	if h.size+len(p) <= chunkSize {
		h.size += len(p)
		return h.chunk.Write(p)
	}

	// Fill out what remains of the current chunk
	nn, err := h.chunk.Write(p[:chunkSize-h.size])
	h.size += nn
	if err != nil {
		return nn, err
	}
	p = p[nn:]

	// If we were given more full chunks, hash them
	for len(p) > chunkSize {
		// At this point, the previous chunk must be full
		h.hashes = h.chunk.Sum(h.hashes)
		h.chunk.Reset()

		n, err := h.chunk.Write(p[:chunkSize])
		nn += n
		if err != nil {
			return nn, err
		}
		p = p[n:]
	}

	// If there's anything left, it's a partial chunk
	if len(p) > 0 {
		// At this point, the previous chunk must be full
		h.hashes = h.chunk.Sum(h.hashes)
		h.chunk.Reset()

		n, err := h.chunk.Write(p)
		h.size = n
		nn += n
		if err != nil {
			return nn, err
		}
	}

	return nn, nil
}

func (h *Ed2k) Sum(b []byte) []byte {
	if len(h.hashes) == 0 {
		return h.chunk.Sum(b)
	}

	hashes := h.chunk.Sum(h.hashes)

	// Keep the new buffer for later resets, in case it was resized
	h.hashes = hashes[:len(h.hashes)]

	hsh := md4.New()
	_, err := hsh.Write(hashes)
	if err != nil {
		panic(err)
	}

	return hsh.Sum(b)
}

func (h *Ed2k) Reset() {
	h.hashes = h.hashes[:0]
	h.chunk.Reset()
	h.size = 0
}

func (h *Ed2k) Size() int {
	return 16
}

func (h *Ed2k) BlockSize() int {
	return chunkSize
}

func (h *Ed2k) SumBlue() (string, error) {
	if len(h.hashes) == 0 {
		return h.toHex(h.chunk), nil
	}

	hashes := h.chunk.Sum(h.hashes)

	// Keep the new buffer for later resets, in case it was resized
	h.hashes = hashes[:len(h.hashes)]

	hsh := md4.New()
	if h.t != nil {
		h.t.Logf("bluehashes: %X", hashes)
	}
	_, err := hsh.Write(hashes)
	if err != nil {
		return "", err
	}

	return h.toHex(hsh), nil
}

// The "bugged" version of the hash.  See https://wiki.anidb.net/Ed2k-hash#How_is_an_ed2k_hash_calculated_exactly? for more info.
func (h *Ed2k) SumRed() (string, error) {
	if len(h.hashes) == 0 && h.size != chunkSize {
		return h.toHex(h.chunk), nil
	}

	hashes := h.chunk.Sum(h.hashes)

	if h.size == chunkSize {
		hashes = append(hashes, emptyMD4...)
	}

	// Keep the new buffer for later resets, in case it was resized
	h.hashes = hashes[:len(h.hashes)]

	hsh := md4.New()

	if h.t != nil {
		h.t.Logf("red hashes: %X", hashes)
	}

	_, err := hsh.Write(hashes)
	if err != nil {
		return "", err
	}

	return h.toHex(hsh), nil
}

// toHex converts an MD4 sum into a string. The given hash must be MD4.
//
// This does the same operation as fmt.Sprintf("%x", hsh.Sum(nil)), but
// with fewer allocations. Honestly, it's likely premature optimization.
func (h *Ed2k) toHex(hsh hash.Hash) string {
	// buf escapes into hsh.Sum, so we can't avoid an allocation for it
	// simply by using an array (like for str below). However, if there
	// is enough space left in the hashes slice, we can use that, since
	// it's already heap-allocated and thus causes no extra allocations.
	var buf []byte
	if cap(h.hashes) >= len(h.hashes) + 16 {
		buf = h.hashes[len(h.hashes):len(h.hashes)+16]
	} else {
		buf = make([]byte, 16)
	}

	hsh.Sum(buf[:0])

	const hex = "0123456789abcdef"
	var str [32]byte
	for i, j := 0, 0; i < 16; i++ {
		b := buf[i]
		str[j], str[j+1] = hex[b>>4], hex[b&0x0F]
		j += 2
	}

	return string(str[:])
}
