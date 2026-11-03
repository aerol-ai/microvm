package firecracker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// A sandbox's rootfs and overlay are sparse: a 10 GiB ext4 image whose
// unwritten blocks are holes, so a new sandbox takes about 90 MiB on the
// host. Stop copies them out of the jailer's chroot and Start copies them
// back in. A plain copy (io.Copy, which is copy_file_range on Linux) reads
// a hole as zeros and writes the zeros, so each copy took the full 10 GiB:
// one Stop and Start turned 90 MiB into 22 GiB, and a second Stop could
// fill the host's disk. copySparse writes only the blocks that hold data.

// sparseBlockSize is the unit copySparse skips: a block of zeros this size
// is left as a hole. 4 KiB is the block size of ext4, xfs and APFS and the
// page size of tmpfs, so it is the smallest hole any of them keeps.
const sparseBlockSize = 4096

// sparseBufSize is how much copySparse reads at a time.
const sparseBufSize = 1 << 20

var zeroBlock = make([]byte, sparseBlockSize)

// byteRange is the half-open byte range [start, end) of a file.
type byteRange struct{ start, end int64 }

// dataRanges returns the ranges of f, a file of size bytes, that may hold
// data. The filesystem lists them (lseek SEEK_DATA / SEEK_HOLE, on ext4, xfs,
// btrfs, tmpfs and APFS), so the holes between them are never read. Where it
// cannot, the rest of the file is one range: still correct, since copySparse
// skips zero blocks it reads, only slower.
func dataRanges(f *os.File, size int64) []byteRange {
	var ranges []byteRange
	for off := int64(0); off < size; {
		data, err := f.Seek(off, unix.SEEK_DATA)
		if errors.Is(err, unix.ENXIO) {
			break // nothing but a hole from off to the end
		}
		if err != nil {
			return append(ranges, byteRange{off, size})
		}
		if data >= size {
			break
		}
		hole, err := f.Seek(data, unix.SEEK_HOLE)
		if err != nil || hole > size {
			hole = size
		}
		ranges = append(ranges, byteRange{data, hole})
		off = hole
	}
	return ranges
}

// copySparse copies the ranges of src to the same offsets in dst, writing
// only the blocks that are not all zeros, then sets dst's length to size.
// Everything it does not write reads back as zeros: dst has src's exact
// bytes, but its zeros are holes, whether src kept them as holes or as
// written blocks. dst must start empty.
func copySparse(dst copyFileDest, src io.ReaderAt, ranges []byteRange, size int64) error {
	buf := make([]byte, sparseBufSize)
	for _, r := range ranges {
		for off := r.start; off < r.end; {
			chunk := buf[:min(int64(len(buf)), r.end-off)]
			if n, err := src.ReadAt(chunk, off); n < len(chunk) {
				if err == nil || errors.Is(err, io.EOF) {
					err = io.ErrUnexpectedEOF
				}
				return fmt.Errorf("read at %d: %w", off, err)
			}
			if err := writeDataBlocks(dst, chunk, off); err != nil {
				return err
			}
			off += int64(len(chunk))
		}
	}
	// Sets the length a trailing hole would otherwise leave short.
	if err := dst.Truncate(size); err != nil {
		return fmt.Errorf("truncate to %d: %w", size, err)
	}
	return nil
}

// writeDataBlocks writes chunk, which belongs at off, to dst: each run of
// blocks that are not all zeros in one write, and nothing for a zero block.
func writeDataBlocks(dst io.WriterAt, chunk []byte, off int64) error {
	runStart := -1
	flush := func(end int) error {
		if runStart < 0 {
			return nil
		}
		if _, err := dst.WriteAt(chunk[runStart:end], off+int64(runStart)); err != nil {
			return fmt.Errorf("write at %d: %w", off+int64(runStart), err)
		}
		runStart = -1
		return nil
	}
	for i := 0; i < len(chunk); i += sparseBlockSize {
		block := chunk[i:min(i+sparseBlockSize, len(chunk))]
		if bytes.Equal(block, zeroBlock[:len(block)]) {
			if err := flush(i); err != nil {
				return err
			}
			continue
		}
		if runStart < 0 {
			runStart = i
		}
	}
	return flush(len(chunk))
}
