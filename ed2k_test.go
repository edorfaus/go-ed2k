package ed2k

import (
	"fmt"
	"testing"
)

// Expected hashes for one complete chunk of zeroes
const zeroOneChunkBlue = "d7def262a127cd79096a108e7a9fc138"
const zeroOneChunkRed = "fc21d9af828f92a8df64beac3357425d"

// Expected hashes for two complete chunks of zeroes
const zeroTwoChunkBlue = "194ee9e4fa79b2ee9f8829284c466051"
const zeroTwoChunkRed = "114b21c63a74b6ca922291a11177dd5c"

func TestNoChunk(t *testing.T) {
	h := New()
	h.setTest(t)

	const targetHash = "31d6cfe0d16ae931b73c59d7e0c089c0"
	verifyBlueRed(t, h, targetHash, targetHash)
}

func TestZeroOneByte(t *testing.T) {
	h := New()
	h.setTest(t)

	verifyWrite(t, h, 1, []byte{0})

	const targetHash = "47c61a0fa8738ba77308a8a600f88e4b"
	verifyBlueRed(t, h, targetHash, targetHash)
}

func TestZeroHalfChunk(t *testing.T) {
	h := New()
	h.setTest(t)

	zf := make([]byte, chunkSize/2)

	verifyWrite(t, h, 1, zf)

	const targetHash = "ca6ea162b58a7e26c7f1830aa4fb9c5c"
	verifyBlueRed(t, h, targetHash, targetHash)
}

func TestZeroOneChunk(t *testing.T) {
	h := New()
	h.setTest(t)

	zf := make([]byte, chunkSize)

	verifyWrite(t, h, 1, zf)

	verifyBlueRed(t, h, zeroOneChunkBlue, zeroOneChunkRed)
}

func TestZeroOneChunkTwoWrites(t *testing.T) {
	h := New()
	h.setTest(t)

	zf := make([]byte, chunkSize/2)

	verifyWrite(t, h, 1, zf)
	verifyWrite(t, h, 2, zf)

	verifyBlueRed(t, h, zeroOneChunkBlue, zeroOneChunkRed)
}

func TestZeroTwoChunk(t *testing.T) {
	h := New()
	h.setTest(t)

	zf := make([]byte, chunkSize*2)

	verifyWrite(t, h, 1, zf)

	verifyBlueRed(t, h, zeroTwoChunkBlue, zeroTwoChunkRed)
}

func TestZeroTwoChunkTwoWrites(t *testing.T) {
	h := New()
	h.setTest(t)

	zf := make([]byte, chunkSize)

	verifyWrite(t, h, 1, zf)
	verifyWrite(t, h, 2, zf)

	verifyBlueRed(t, h, zeroTwoChunkBlue, zeroTwoChunkRed)
}

func TestZeroTwoChunkThreeWrites(t *testing.T) {
	h := New()
	h.setTest(t)

	zf := make([]byte, chunkSize)

	// This tests writes that cross the chunk boundary, without being
	// larger than a chunk.
	verifyWrite(t, h, 1, zf[:chunkSize/2])
	verifyWrite(t, h, 2, zf)
	verifyWrite(t, h, 3, zf[:chunkSize/2])

	verifyBlueRed(t, h, zeroTwoChunkBlue, zeroTwoChunkRed)
}

func TestZeroOverOneChunk(t *testing.T) {
	h := New()
	h.setTest(t)

	zf := make([]byte, chunkSize)

	verifyWrite(t, h, 1, zf[:1])
	verifyWrite(t, h, 2, zf)

	const targetHash = "06329e9dba1373512c06386fe29e3c65"
	verifyBlueRed(t, h, targetHash, targetHash)
}

func TestZeroOneAndHalfChunk(t *testing.T) {
	h := New()
	h.setTest(t)

	zf := make([]byte, chunkSize)

	verifyWrite(t, h, 1, zf)
	verifyWrite(t, h, 2, zf[:chunkSize/2])

	const targetHash = "7dc39579c6e15343361a37d3d4e5b9d2"
	verifyBlueRed(t, h, targetHash, targetHash)
}

func TestZeroOverTwoChunks(t *testing.T) {
	h := New()
	h.setTest(t)

	zf := make([]byte, chunkSize)

	verifyWrite(t, h, 1, zf)
	verifyWrite(t, h, 2, zf[:1])
	verifyWrite(t, h, 3, zf)

	const targetHash = "e57f824d28f69fe90864e17673668457"
	verifyBlueRed(t, h, targetHash, targetHash)
}

func TestSizes(t *testing.T) {
	h := New()
	s, bs := h.Size(), h.BlockSize()
	if s != 16 {
		t.Errorf("Bad Size(): expected %v, got %v", 16, s)
	}
	if bs != chunkSize {
		t.Errorf("Bad BlockSize(): expected %v, got %v", chunkSize, bs)
	}
	if chunkSize != 9728000 {
		t.Errorf("Bad chunkSize: expected %v, got %v", 9728000, chunkSize)
	}
}

func TestReset(t *testing.T) {
	h := New()

	// For this test, we don't care whether the sums have the expected
	// values, only whether they're consistent - so don't verify them,
	// just grab them to compare against the values after the reset.

	getBlueRed := func() (blue, red string) {
		t.Helper()
		var err error
		if blue, err = h.SumBlue(); err != nil {
			t.Fatalf("SumBlue failed: %v", err)
		}
		if red, err = h.SumRed(); err != nil {
			t.Fatalf("SumRed failed: %v", err)
		}
		return blue, red
	}

	emptyBlue, emptyRed := getBlueRed()

	// Reset should not affect an empty hash
	h.Reset()
	verifyBlueRed(t, h, emptyBlue, emptyRed)

	zf := make([]byte, chunkSize)

	verifyWrite(t, h, 1, zf)

	otherBlue, otherRed := getBlueRed()

	if otherBlue == emptyBlue || otherRed == emptyRed {
		t.Logf("Empty blue/red: %s / %s", emptyBlue, emptyRed)
		t.Logf("Other blue/red: %s / %s", otherBlue, otherRed)
		t.Fatalf("Write did not change the sums, so cannot test Reset")
	}

	h.Reset()
	verifyBlueRed(t, h, emptyBlue, emptyRed)

	verifyWrite(t, h, 2, zf)
	verifyBlueRed(t, h, otherBlue, otherRed)
}

func verifyWrite(t *testing.T, h *Ed2k, i int, b []byte) {
	t.Helper()

	n, err := h.Write(b)
	if err != nil {
		t.Logf("Write %v failed: %v", i, err)
		if n != len(b) {
			t.Logf("Bad size: expected %v, got %v", len(b), n)
		}
		t.FailNow()
	}
	if n != len(b) {
		t.Fatalf("Write %v: bad size: expected %d, got %d", i, len(b), n)
	}
}

func verifyBlueRed(t *testing.T, h *Ed2k, expectBlue, expectRed string) {
	t.Helper()

	gotBlue, errBlue := h.SumBlue()
	gotRed, errRed := h.SumRed()

	if errBlue != nil {
		t.Errorf("SumBlue error: %v", errBlue)
	}
	if errRed != nil {
		t.Errorf("SumRed error: %v", errRed)
	}

	if gotBlue != expectBlue {
		t.Errorf("blue failed: %q", gotBlue)
		t.Errorf("   expected: %q", expectBlue)
	} else {
		t.Logf("blue passed: %q", gotBlue)
	}

	if gotRed != expectRed {
		t.Errorf("red  failed: %q", gotRed)
		t.Errorf("   expected: %q", expectRed)
	} else {
		t.Logf("red  passed: %q", gotRed)
	}

	// Also check that Sum() matches blue
	sum := fmt.Sprintf("%x", h.Sum(nil))
	if sum != expectBlue {
		t.Errorf("Sum  failed: %q", sum)
		t.Errorf("   expected: %q", expectBlue)
	} else {
		t.Logf("Sum  passed: %q", sum)
	}
}
