/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package seekablezstd

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"

	seekable "github.com/SaveTheRbtz/zstd-seekable-format-go/pkg"
	"github.com/klauspost/compress/zstd"

	"github.com/Microsoft/hcsshim/ext4/dmverity"
)

// Encode encodes an EROFS image to seekable zstd without dm-verity.
//
// Output format: [zstd frames][seek table]
func Encode(ctx context.Context, input io.ReadSeeker, output io.Writer, chunkSize int, verbose bool) (*EncodeResult, error) {
	return encodeInternal(ctx, input, output, chunkSize, false, verbose)
}

// EncodeWithDMVerity encodes an EROFS image to seekable zstd with dm-verity.
//
// Output format: [zstd frames][dm-verity superblock+tree][seek table]
//
// The seek table is placed at EOF per the zstd seekable format spec, which
// allows standard seekable zstd readers to parse it. The dm-verity data
// sits between frames and seek table.
func EncodeWithDMVerity(ctx context.Context, input io.ReadSeeker, output io.Writer, chunkSize int, verbose bool) (*EncodeResult, error) {
	return encodeInternal(ctx, input, output, chunkSize, true, verbose)
}

func encodeInternal(ctx context.Context, input io.ReadSeeker, output io.Writer, chunkSize int, includeDMVerity bool, verbose bool) (*EncodeResult, error) {
	// ctx is reserved for future cancellation / timeouts.
	_ = ctx

	if chunkSize == 0 {
		chunkSize = DefaultChunkSize
	}

	log := newLogger("[ENCODE]", verbose)
	result := &EncodeResult{}

	// Step 1: Get input size
	size, err := getInputSize(input)
	if err != nil {
		return nil, err
	}
	result.UncompressedSize = size

	log.Printf("Input size: %d bytes\n", size)
	log.Printf("Chunk size: %d bytes (%d chunks expected)\n", chunkSize, (size+int64(chunkSize)-1)/int64(chunkSize))

	var (
		tree       []byte
		rootDigest string
		paddedSize int64
	)
	if includeDMVerity {
		// Step 2: Compute dm-verity merkle tree
		tree, rootDigest, paddedSize, err = computeDMVerity(input, size, log)
		if err != nil {
			return nil, err
		}
		result.RootDigest = rootDigest
		result.TreeSize = len(tree)
	}

	// Step 3: Create encoders
	seekableEnc, cleanup, err := createEncoders()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Step 4: Compress input in chunks
	numFrames, framesWritten, err := compressChunks(input, output, seekableEnc, chunkSize, log)
	if err != nil {
		return nil, err
	}
	result.NumFrames = numFrames
	result.FramesEndOffset = framesWritten

	log.Printf("Frames complete: %d frames, %d bytes total\n", numFrames, framesWritten)
	if includeDMVerity {
		log.Printf("dmverity-offset (start of dm-verity / end of frames): %d\n", framesWritten)
	} else {
		log.Printf("end-of-frames offset: %d\n", framesWritten)
	}

	var dmverityWritten int64
	if includeDMVerity {
		// Step 5: Write dm-verity data
		dmverityWritten, err = writeDMVerityData(output, tree, paddedSize, log)
		if err != nil {
			return nil, err
		}
		result.DMVeritySize = dmverityWritten
	}

	// Step 6: Write seek table at EOF
	seekTableBytes, err := seekableEnc.EndStream()
	if err != nil {
		return nil, fmt.Errorf("generate seek table: %w", err)
	}

	log.Printf("Writing seek table at offset %d...\n", framesWritten+dmverityWritten)

	seekWritten, err := writeFull(output, seekTableBytes)
	if err != nil {
		return nil, fmt.Errorf("write seek table: %w", err)
	}
	result.SeekTableSize = seekWritten

	log.Printf("Seek table: %d bytes\n", seekWritten)
	if len(seekTableBytes) >= 4 {
		log.Printf("Final 4 bytes (seekable magic): %x\n", seekTableBytes[len(seekTableBytes)-4:])
	}

	// Calculate totals
	result.TotalSize = framesWritten + dmverityWritten + int64(seekWritten)

	// Print summary
	if verbose {
		printLayoutDiagram(result, seekTableBytes, log)
	}

	return result, nil
}

// getInputSize returns the size of the input and resets to start.
func getInputSize(input io.ReadSeeker) (int64, error) {
	size, err := input.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, fmt.Errorf("seek to end: %w", err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("seek to start: %w", err)
	}
	return size, nil
}

// computeDMVerity computes the merkle tree and root hash from input, padding
// to a 4KiB boundary if needed.
//
// Returns: tree bytes, root digest, padded size.
func computeDMVerity(input io.ReadSeeker, size int64, log *logger) ([]byte, string, int64, error) {
	log.Printf("Computing dm-verity merkle tree...\n")

	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return nil, "", 0, fmt.Errorf("seek to start for dm-verity: %w", err)
	}

	paddedSize := roundUpToBlock(size, DMVerityBlockSize)
	padLen := paddedSize - size

	var r io.Reader = io.LimitReader(input, size)
	if padLen > 0 {
		r = io.MultiReader(r, &zeroReader{n: padLen})
	}

	tree, err := dmverity.MerkleTree(r)
	if err != nil {
		return nil, "", 0, fmt.Errorf("compute merkle tree: %w", err)
	}

	rootHash := dmverity.RootHash(tree)
	rootDigest := fmt.Sprintf("%x", rootHash)

	log.Printf("DM-verity tree size: %d bytes\n", len(tree))
	log.Printf("DM-verity root hash: %s\n", rootDigest)
	if padLen > 0 {
		log.Printf("DM-verity padded data size: %d bytes (added %d zero bytes)\n", paddedSize, padLen)
	}

	// Reset for compression
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return nil, "", 0, fmt.Errorf("seek to start for compression: %w", err)
	}

	return tree, rootDigest, paddedSize, nil
}

// createEncoders creates the zstd and seekable encoders.
// Returns the seekable encoder and a cleanup function.
func createEncoders() (seekable.Encoder, func(), error) {
	zstdEnc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, nil, fmt.Errorf("create zstd encoder: %w", err)
	}

	seekableEnc, err := seekable.NewEncoder(zstdEnc)
	if err != nil {
		zstdEnc.Close()
		return nil, nil, fmt.Errorf("create seekable encoder: %w", err)
	}

	cleanup := func() {
		zstdEnc.Close()
	}

	return seekableEnc, cleanup, nil
}

// compressChunks reads input in chunks, compresses each, and writes to output.
func compressChunks(input io.Reader, output io.Writer, encoder seekable.Encoder, chunkSize int, log *logger) (int, int64, error) {
	log.Printf("Compressing in %d-byte chunks...\n", chunkSize)
	log.Printf("  %-8s  %-14s  %-14s  %-8s  %s\n", "Frame", "Input", "Compressed", "Ratio", "Output Offset")
	log.Printf("  %-8s  %-14s  %-14s  %-8s  %s\n", "-----", "-----------", "-----------", "-----", "-------------")

	chunk := make([]byte, chunkSize)
	var totalWritten int64
	numFrames := 0

	for {
		n, readErr := io.ReadFull(input, chunk)
		if n > 0 {
			compressed, err := encoder.Encode(chunk[:n])
			if err != nil {
				return 0, 0, fmt.Errorf("encode chunk %d: %w", numFrames, err)
			}

			written, err := writeFull(output, compressed)
			if err != nil {
				return 0, 0, fmt.Errorf("write frame %d: %w", numFrames, err)
			}

			ratio := float64(written) / float64(n) * 100
			log.Printf("  %-8d  %6d bytes   %6d bytes   %-7.1f%%  %d\n",
				numFrames, n, written, ratio, totalWritten)

			totalWritten += int64(written)
			numFrames++
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			return 0, 0, fmt.Errorf("read input: %w", readErr)
		}
	}

	return numFrames, totalWritten, nil
}

// writeDMVerityData writes the superblock, padding, and merkle tree.
func writeDMVerityData(output io.Writer, tree []byte, dataSize int64, log *logger) (int64, error) {
	log.Printf("Writing dm-verity data...\n")

	var totalWritten int64

	// Write superblock
	dmvSB := dmverity.NewDMVeritySuperblock(uint64(dataSize))
	if err := binary.Write(output, binary.LittleEndian, dmvSB); err != nil {
		return 0, fmt.Errorf("write dm-verity superblock: %w", err)
	}
	totalWritten += SuperblockSize

	// Write padding to 4KB boundary
	padding := make([]byte, SuperblockPadding)
	if _, err := writeFull(output, padding); err != nil {
		return 0, fmt.Errorf("write superblock padding: %w", err)
	}
	totalWritten += SuperblockPadding

	// Write merkle tree
	treeWritten, err := writeFull(output, tree)
	if err != nil {
		return 0, fmt.Errorf("write merkle tree: %w", err)
	}
	totalWritten += int64(treeWritten)

	log.Printf("DM-verity superblock: %d bytes + %d padding\n", SuperblockSize, SuperblockPadding)
	log.Printf("DM-verity tree: %d bytes\n", treeWritten)
	log.Printf("DM-verity total: %d bytes\n", totalWritten)

	return totalWritten, nil
}

// printLayoutDiagram prints the ASCII box visualization of the output layout.
func printLayoutDiagram(result *EncodeResult, seekTableBytes []byte, log *logger) {
	dmverityEnd := result.FramesEndOffset + result.DMVeritySize

	log.Printf("=== COMPLETE ===\n")
	log.Printf("Compression: %d -> %d bytes (%.1f%% of original)\n",
		result.UncompressedSize, result.TotalSize,
		float64(result.TotalSize)/float64(result.UncompressedSize)*100)
	log.Print("\n")

	fmt.Printf("[ENCODE] ┌────────────────────────────────────────────────────┐\n")
	fmt.Printf("[ENCODE] │              OUTPUT FILE LAYOUT                    │\n")
	fmt.Printf("[ENCODE] ├────────────────────────────────────────────────────┤\n")
	boxLine("[ENCODE]", "SECTION 1: Zstd Compressed Frames")
	boxLine("[ENCODE]", "  Offset: 0")
	boxLine("[ENCODE]", fmt.Sprintf("  Size:   %d bytes (%d frames)", result.FramesEndOffset, result.NumFrames))
	boxLine("[ENCODE]", "  Each frame: independent zstd stream")
	fmt.Printf("[ENCODE] ├────────────────────────────────────────────────────┤\n")
	boxLine("[ENCODE]", "SECTION 2: DM-Verity Data")
	boxLine("[ENCODE]", fmt.Sprintf("  Offset: %d", result.FramesEndOffset))
	boxLine("[ENCODE]", fmt.Sprintf("  Size:   %d bytes", result.DMVeritySize))
	boxLine("[ENCODE]", fmt.Sprintf("  Superblock: %d bytes (padded to %d)", SuperblockSize, DMVerityBlockSize))
	boxLine("[ENCODE]", fmt.Sprintf("  Merkle tree: %d bytes", result.TreeSize))
	boxLine("[ENCODE]", fmt.Sprintf("  Root hash: %s", result.RootDigest))
	fmt.Printf("[ENCODE] ├────────────────────────────────────────────────────┤\n")
	boxLine("[ENCODE]", "SECTION 3: Seek Table (standard zstd seekable)")
	boxLine("[ENCODE]", fmt.Sprintf("  Offset: %d", dmverityEnd))
	boxLine("[ENCODE]", fmt.Sprintf("  Size:   %d bytes", result.SeekTableSize))
	boxLine("[ENCODE]", "  Format: skippable frame with frame index")
	if len(seekTableBytes) >= 4 {
		boxLine("[ENCODE]", fmt.Sprintf("  Magic:  0x%X (at EOF-4)", seekTableBytes[len(seekTableBytes)-4:]))
	}
	fmt.Printf("[ENCODE] ├────────────────────────────────────────────────────┤\n")
	boxLine("[ENCODE]", fmt.Sprintf("TOTAL: %d bytes", result.TotalSize))
	boxLine("[ENCODE]", fmt.Sprintf("EOF at offset: %d", result.TotalSize))
	fmt.Printf("[ENCODE] └────────────────────────────────────────────────────┘\n")
}

// boxLine prints a line inside an ASCII box with consistent width.
func boxLine(prefix, content string) {
	const boxWidth = 50
	padding := boxWidth - len(content)
	if padding < 0 {
		padding = 0
		content = content[:boxWidth]
	}
	fmt.Printf("%s │ %s%*s │\n", prefix, content, padding, "")
}
