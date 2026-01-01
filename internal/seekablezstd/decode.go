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
	"encoding/binary"
	"fmt"
	"io"
	"os"

	seekable "github.com/SaveTheRbtz/zstd-seekable-format-go/pkg"
	"github.com/klauspost/compress/zstd"

	"github.com/Microsoft/hcsshim/ext4/dmverity"
)

// Decode decompresses a seekable zstd blob and optionally verifies dm-verity.
//
// The seekable reader automatically handles finding the seek table at EOF
// and reading frames at their correct offsets, even with dm-verity data
// between frames and seek table.
//
// Note: dm-verity verification requires the output to be an *os.File (so we can
// seek and re-read it to compute the merkle tree).
func Decode(input *os.File, output io.Writer, dmverityOffset int64, expectedRootDigest string, verbose bool) (*DecodeResult, error) {
	log := newLogger("[DECODE]", verbose)
	result := &DecodeResult{}

	// Step 1: Get file info
	stat, err := input.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat input: %w", err)
	}
	fileSize := stat.Size()

	log.Printf("Input file size: %d bytes\n", fileSize)
	if dmverityOffset > 0 {
		log.Printf("dmverity-offset (start of dm-verity / end of frames): %d\n", dmverityOffset)
		log.Printf("DM-verity data size: %d bytes\n", fileSize-dmverityOffset)
	}

	// Step 2: Validate seekable magic
	if err := validateSeekableMagic(input, log); err != nil {
		return nil, err
	}

	// Step 3: Create seekable reader and decompress
	log.Printf("Creating seekable reader...\n")

	decompressedSize, err := decompressWithSeekableReader(input, output)
	if err != nil {
		return nil, err
	}
	result.DecompressedSize = decompressedSize

	log.Printf("Decompressed: %d bytes\n", decompressedSize)

	// Step 4: Verify dm-verity if requested
	if expectedRootDigest != "" {
		outFile, ok := output.(*os.File)
		if !ok {
			return nil, fmt.Errorf("dm-verity verification requires output to be *os.File")
		}
		valid, actualDigest, err := verifyDMVerity(outFile, expectedRootDigest, log)
		if err != nil {
			return nil, err
		}
		result.DMVerityValid = valid
		result.ActualRootDigest = actualDigest

		if !valid {
			return result, fmt.Errorf("dm-verity verification failed: expected %s, got %s",
				expectedRootDigest, actualDigest)
		}
	}

	log.Printf("=== COMPLETE ===\n")
	return result, nil
}

// validateSeekableMagic checks the magic bytes at EOF.
// If log is non-nil, progress is logged.
func validateSeekableMagic(input *os.File, log *logger) error {
	if log != nil {
		log.Printf("Checking seekable magic at EOF...\n")
	}

	if _, err := input.Seek(-4, io.SeekEnd); err != nil {
		return fmt.Errorf("seek to magic: %w", err)
	}

	var magic uint32
	if err := binary.Read(input, binary.LittleEndian, &magic); err != nil {
		return fmt.Errorf("read magic: %w", err)
	}

	if magic != SeekableMagic {
		return fmt.Errorf("invalid seekable magic: got 0x%08X, want 0x%08X", magic, SeekableMagic)
	}

	if log != nil {
		log.Printf("Seekable magic OK: 0x%08X\n", magic)
	}

	// Reset to beginning
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek to start: %w", err)
	}

	return nil
}

// decompressWithSeekableReader creates a seekable reader and decompresses all data.
func decompressWithSeekableReader(input *os.File, output io.Writer) (int64, error) {
	zstdDec, err := zstd.NewReader(nil)
	if err != nil {
		return 0, fmt.Errorf("create zstd decoder: %w", err)
	}
	defer zstdDec.Close()

	reader, err := seekable.NewReader(input, zstdDec)
	if err != nil {
		return 0, fmt.Errorf("create seekable reader: %w", err)
	}
	defer reader.Close()

	n, err := io.Copy(output, reader)
	if err != nil {
		return 0, fmt.Errorf("decompress: %w", err)
	}

	return n, nil
}

// verifyDMVerity computes and verifies the dm-verity hash.
// Requires an *os.File so we can seek back and re-read the decompressed data.
func verifyDMVerity(output *os.File, expectedDigest string, log *logger) (bool, string, error) {
	log.Printf("Verifying dm-verity...\n")
	log.Printf("Expected root digest: %s\n", expectedDigest)

	stat, err := output.Stat()
	if err != nil {
		return false, "", fmt.Errorf("stat output: %w", err)
	}
	size := stat.Size()

	if _, err := output.Seek(0, io.SeekStart); err != nil {
		return false, "", fmt.Errorf("seek output to start: %w", err)
	}

	paddedSize := roundUpToBlock(size, DMVerityBlockSize)
	padLen := paddedSize - size

	var r io.Reader = io.LimitReader(output, size)
	if padLen > 0 {
		r = io.MultiReader(r, &zeroReader{n: padLen})
		log.Printf("DM-verity padded data size: %d bytes (added %d zero bytes)\n", paddedSize, padLen)
	}

	tree, err := dmverity.MerkleTree(r)
	if err != nil {
		return false, "", fmt.Errorf("compute verification merkle tree: %w", err)
	}

	rootHash := dmverity.RootHash(tree)
	actualDigest := fmt.Sprintf("%x", rootHash)
	valid := actualDigest == expectedDigest

	log.Printf("Actual root digest:   %s\n", actualDigest)
	if valid {
		log.Printf("DM-verity: VALID\n")
	} else {
		log.Printf("DM-verity: MISMATCH\n")
	}

	return valid, actualDigest, nil
}

// Inspect prints detailed information about a seekable blob without fully decoding.
func Inspect(input *os.File, verbose bool) error {
	stat, err := input.Stat()
	if err != nil {
		return fmt.Errorf("stat input: %w", err)
	}
	fileSize := stat.Size()

	fmt.Printf("=== Seekable EROFS Blob Inspection ===\n")
	fmt.Printf("File size: %d bytes\n", fileSize)

	// Validate magic (no logging in inspect header)
	if err := validateSeekableMagic(input, nil); err != nil {
		fmt.Printf("Seekable magic: INVALID\n")
		return err
	}
	fmt.Printf("Seekable magic: 0x%08X (valid)\n", SeekableMagic)

	// Read seek table info
	info, err := readSeekTableInfo(input, fileSize)
	if err != nil {
		return err
	}

	fmt.Printf("Number of frames: %d\n", info.NumFrames)
	fmt.Printf("Checksum enabled: %v\n", info.ChecksumFlag)
	fmt.Printf("Seek table size: %d bytes\n", info.TableSize)
	fmt.Printf("Seek table starts at: %d\n", info.TableStart)

	// Parse and print frame entries
	frames, err := parseFrameEntries(input, info)
	if err != nil {
		return err
	}

	printFrameTable(frames, verbose)

	// Print summary
	printInspectSummary(frames, info)

	// Validate with seekable reader
	if err := validateWithReader(input); err != nil {
		fmt.Printf("\nSeekable reader: failed (%v)\n", err)
	} else {
		fmt.Printf("\nSeekable reader: valid (can decompress)\n")
	}

	fmt.Printf("=====================================\n")
	return nil
}

// readSeekTableInfo parses the seek table footer and returns metadata.
func readSeekTableInfo(input *os.File, fileSize int64) (*SeekTableInfo, error) {
	if _, err := input.Seek(-SeekTableFooterSize, io.SeekEnd); err != nil {
		return nil, fmt.Errorf("seek to footer: %w", err)
	}

	footer := make([]byte, SeekTableFooterSize)
	if _, err := io.ReadFull(input, footer); err != nil {
		return nil, fmt.Errorf("read footer: %w", err)
	}

	info := &SeekTableInfo{
		NumFrames:    binary.LittleEndian.Uint32(footer[0:4]),
		ChecksumFlag: (footer[4]>>7)&1 == 1,
	}

	// Entry size depends on checksum flag
	info.EntrySize = 8
	if info.ChecksumFlag {
		info.EntrySize = 12
	}

	// Total size: header (8) + entries + footer (9)
	info.TableSize = SeekTableHeaderSize + (int(info.NumFrames) * info.EntrySize) + SeekTableFooterSize
	info.TableStart = fileSize - int64(info.TableSize)

	return info, nil
}

// parseFrameEntries reads all frame entries from the seek table.
func parseFrameEntries(input *os.File, info *SeekTableInfo) ([]FrameInfo, error) {
	// Seek to start of entries (after skippable frame header)
	if _, err := input.Seek(info.TableStart+SeekTableHeaderSize, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek to entries: %w", err)
	}

	frames := make([]FrameInfo, info.NumFrames)
	var offset uint64

	for i := uint32(0); i < info.NumFrames; i++ {
		entry := make([]byte, info.EntrySize)
		if _, err := io.ReadFull(input, entry); err != nil {
			return nil, fmt.Errorf("read entry %d: %w", i, err)
		}

		frames[i] = FrameInfo{
			Index:            i,
			CompressedSize:   binary.LittleEndian.Uint32(entry[0:4]),
			DecompressedSize: binary.LittleEndian.Uint32(entry[4:8]),
			Offset:           offset,
		}

		if info.ChecksumFlag && len(entry) >= 12 {
			frames[i].Checksum = binary.LittleEndian.Uint32(entry[8:12])
		}

		offset += uint64(frames[i].CompressedSize)
	}

	return frames, nil
}

// printFrameTable prints the frame details table.
func printFrameTable(frames []FrameInfo, verbose bool) {
	fmt.Printf("\n--- Frame Details ---\n")
	fmt.Printf("%-8s  %-14s  %-14s  %-10s  %-8s\n",
		"Frame", "Compressed", "Decompressed", "Ratio", "Offset")
	fmt.Printf("%-8s  %-14s  %-14s  %-10s  %-8s\n",
		"-----", "----------", "------------", "-----", "------")

	numFrames := len(frames)
	for i, f := range frames {
		if verbose || numFrames <= 20 {
			printFrameRow(f)
		} else if i < 3 {
			printFrameRow(f)
		} else if i == 3 {
			fmt.Printf("... (%d more frames) ...\n", numFrames-6)
		} else if i >= numFrames-3 {
			printFrameRow(f)
		}
	}
}

// printFrameRow prints a single frame row.
func printFrameRow(f FrameInfo) {
	fmt.Printf("%-8d  %6d bytes   %6d bytes   %6.1f%%    %d\n",
		f.Index, f.CompressedSize, f.DecompressedSize, f.Ratio(), f.Offset)
}

// printInspectSummary prints the summary section.
func printInspectSummary(frames []FrameInfo, info *SeekTableInfo) {
	var totalComp, totalDecomp uint64
	for _, f := range frames {
		totalComp += uint64(f.CompressedSize)
		totalDecomp += uint64(f.DecompressedSize)
	}

	fmt.Printf("\n--- Summary ---\n")
	fmt.Printf("Total compressed (frames): %d bytes\n", totalComp)
	fmt.Printf("Total decompressed: %d bytes\n", totalDecomp)
	if totalDecomp > 0 {
		fmt.Printf("Overall ratio: %.1f%%\n", float64(totalComp)/float64(totalDecomp)*100)
	}
	fmt.Printf("Frames end at offset: %d\n", totalComp)

	middleSize := info.TableStart - int64(totalComp)
	if middleSize > 0 {
		fmt.Printf("Middle region (dm-verity): %d..%d (%d bytes)\n",
			totalComp, info.TableStart, middleSize)
	} else {
		fmt.Printf("Middle region: empty (no dm-verity)\n")
	}
}

// validateWithReader creates a seekable reader to validate the format.
func validateWithReader(input *os.File) error {
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return err
	}

	zstdDec, err := zstd.NewReader(nil)
	if err != nil {
		return err
	}
	defer zstdDec.Close()

	reader, err := seekable.NewReader(input, zstdDec)
	if err != nil {
		return err
	}
	defer reader.Close()

	return nil
}
