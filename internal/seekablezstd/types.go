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

import "fmt"

// OCI annotation keys (future snapshotter integration).
const (
	AnnotationSeekableZstd = "dev.containerd.erofs.zstd.seekable"

	// AnnotationDMVerityRootDigest is the dm-verity root hash (hex or OCI digest string; design TBD).
	AnnotationDMVerityRootDigest = "dev.containerd.erofs.dmverity.root_digest"

	// AnnotationDMVerityOffset is the byte offset where dm-verity data begins.
	// In our on-disk layout with dm-verity enabled, this equals the end of zstd frames.
	AnnotationDMVerityOffset = "dev.containerd.erofs.dmverity.offset"

	// AnnotationDMVerityBlockSize is the dm-verity block size (default 4096).
	AnnotationDMVerityBlockSize = "dev.containerd.erofs.dmverity.block_size"
)

// Format constants
const (
	// DefaultChunkSize is the default size for compression chunks (4 MiB).
	DefaultChunkSize = 4 * 1024 * 1024

	// DMVerityBlockSize is the block size used by dm-verity (4 KiB).
	DMVerityBlockSize = 4096

	// SuperblockSize is the size of the dm-verity superblock.
	SuperblockSize = 512

	// SuperblockPadding pads the superblock to a 4KB boundary.
	SuperblockPadding = DMVerityBlockSize - SuperblockSize

	// SeekableMagic is the 4-byte magic at EOF of a seekable zstd stream.
	// Defined by the zstd seekable format spec (RFC-style extension).
	SeekableMagic uint32 = 0x8F92EAB1

	// SeekTableFooterSize is the size of the seek table footer (numFrames + descriptor + magic).
	SeekTableFooterSize = 9

	// SeekTableHeaderSize is the size of the skippable frame header (magic + size).
	SeekTableHeaderSize = 8
)

// EncodeResult contains metadata about the encoded blob.
type EncodeResult struct {
	// TotalSize is the total size of the output blob.
	TotalSize int64

	// FramesEndOffset is the byte offset where compressed frames end
	// (and dm-verity data begins if dm-verity is enabled).
	FramesEndOffset int64

	// UncompressedSize is the size of the original input.
	UncompressedSize int64

	// RootDigest is the dm-verity root hash as a hex string.
	RootDigest string

	// NumFrames is the number of compressed zstd frames.
	NumFrames int

	// DMVeritySize is the size of the dm-verity section (superblock + padding + tree).
	DMVeritySize int64

	// SeekTableSize is the size of the seek table.
	SeekTableSize int

	// TreeSize is the size of the merkle tree.
	TreeSize int
}

// DecodeResult contains info about the decoded blob.
type DecodeResult struct {
	// DecompressedSize is the size of the decompressed data.
	DecompressedSize int64

	// DMVerityValid indicates if dm-verity verification passed.
	DMVerityValid bool

	// ActualRootDigest is the computed dm-verity root hash.
	ActualRootDigest string
}

// SeekTableInfo contains parsed seek table metadata.
type SeekTableInfo struct {
	// NumFrames is the number of compressed frames.
	NumFrames uint32

	// ChecksumFlag indicates if checksums are present in entries.
	ChecksumFlag bool

	// EntrySize is the size of each entry (8 or 12 bytes).
	EntrySize int

	// TableSize is the total size of the seek table including header and footer.
	TableSize int

	// TableStart is the byte offset where the seek table begins.
	TableStart int64
}

// FrameInfo contains per-frame metadata from the seek table.
type FrameInfo struct {
	// Index is the frame number (0-based).
	Index uint32

	// CompressedSize is the size of the compressed frame.
	CompressedSize uint32

	// DecompressedSize is the size of the decompressed data.
	DecompressedSize uint32

	// Offset is the byte offset in the file where this frame starts.
	Offset uint64

	// Checksum is the frame checksum (if present).
	Checksum uint32
}

// Ratio returns the compression ratio as a percentage.
func (f *FrameInfo) Ratio() float64 {
	if f.DecompressedSize == 0 {
		return 0
	}
	return float64(f.CompressedSize) / float64(f.DecompressedSize) * 100
}

// logger provides conditional verbose output.
type logger struct {
	prefix  string
	enabled bool
}

// newLogger creates a logger with the given prefix.
func newLogger(prefix string, enabled bool) *logger {
	return &logger{prefix: prefix, enabled: enabled}
}

// Printf prints a formatted message if logging is enabled.
func (l *logger) Printf(format string, args ...interface{}) {
	if l.enabled {
		fmt.Printf("%s %s", l.prefix, fmt.Sprintf(format, args...))
	}
}

// Print prints a message if logging is enabled.
func (l *logger) Print(msg string) {
	if l.enabled {
		fmt.Printf("%s %s", l.prefix, msg)
	}
}

