package ed2k

import (
	"fmt"
	"hash"
	"testing"

	"golang.org/x/crypto/md4"
)

// chunkSize is the size of each chunk of the ed2k hash, in bytes.
const chunkSize = 9728000

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
		return fmt.Sprintf("%x", h.chunk.Sum(nil)), nil
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

	bhash := hsh.Sum([]byte{})
	return fmt.Sprintf("%x", bhash), nil
}

// The "bugged" version of the hash.  See https://wiki.anidb.net/Ed2k-hash#How_is_an_ed2k_hash_calculated_exactly? for more info.
func (h *Ed2k) SumRed() (string, error) {
	if len(h.hashes) == 0 && h.size != chunkSize {
		return fmt.Sprintf("%x", h.chunk.Sum(nil)), nil
	}

	hashes := h.chunk.Sum(h.hashes)

	if h.size == chunkSize {
		hashes = md4.New().Sum(hashes)
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

	bhash := hsh.Sum([]byte{})
	return fmt.Sprintf("%x", bhash), nil
}
