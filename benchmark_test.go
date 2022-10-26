package ed2k

import (
	"testing"
)

func BenchmarkNewSum(b *testing.B) {
	zf := make([]byte, chunkSize*2)

	forSizes := func(totSize, blockSize int) func(*testing.B) {
		block := zf[:blockSize]
		blockCount := totSize / blockSize
		outBuf := make([]byte, 0, 16)
		return func(b *testing.B) {
			for n := 0; n < b.N; n++ {
				h := New()
				for i := 0; i < blockCount; i++ {
					h.Write(block)
				}
				h.Sum(outBuf)
			}
		}
	}

	runBlocks := func(name string, totSize int) {
		b.Run(name, func(b *testing.B) {
			b.Run("blk4K", forSizes(totSize, 4096))
			b.Run("blk1M", forSizes(totSize, 1024*1024))
			if totSize >= chunkSize {
				b.Run("blk1C", forSizes(totSize, chunkSize))
			}
			if totSize >= chunkSize*2 {
				b.Run("blk2C", forSizes(totSize, chunkSize*2))
			}
		})
	}

	runBlocks("szHC", chunkSize/2)
	runBlocks("sz1C", chunkSize)
	runBlocks("sz20M", 20*1024*1024)
	runBlocks("sz100M", 100*1024*1024)
}
