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
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoundTrip(t *testing.T) {
	// Create test data: 256 KB (4 chunks with 64 KB chunk size)
	original := make([]byte, 256*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}

	// Encode to a temp file (library needs io.ReadSeeker for reading)
	tmpFile, err := os.CreateTemp("", "seekable-test-*.bin")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Encode with verbose=true to see progress
	result, err := EncodeWithDMVerity(context.Background(),
		bytes.NewReader(original), tmpFile, 64*1024, true /* verbose */)
	require.NoError(t, err)

	t.Logf("Encoded: %d -> %d bytes, dmverity-offset=%d, dm-verity digest=%s, frames=%d",
		result.UncompressedSize, result.TotalSize,
		result.FramesEndOffset, result.RootDigest, result.NumFrames)

	// Should have 4 frames with 64KB chunk size for 256KB input
	require.Equal(t, 4, result.NumFrames, "expected 4 frames")

	// Verify seek table magic at EOF
	_, err = tmpFile.Seek(-4, io.SeekEnd)
	require.NoError(t, err)

	var magic uint32
	err = binary.Read(tmpFile, binary.LittleEndian, &magic)
	require.NoError(t, err)
	require.Equal(t, uint32(SeekableMagic), magic, "seek table magic at EOF")

	// Rewind for reading
	_, err = tmpFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	// Decode with verbose=true
	outputFile, err := os.CreateTemp("", "decoded-*.bin")
	require.NoError(t, err)
	defer os.Remove(outputFile.Name())
	defer outputFile.Close()

	decResult, err := Decode(tmpFile, outputFile, result.FramesEndOffset, result.RootDigest, true /* verbose */)
	require.NoError(t, err)
	require.True(t, decResult.DMVerityValid, "dm-verity should be valid")
	require.Equal(t, int64(len(original)), decResult.DecompressedSize)

	// Read back and verify content matches
	_, err = outputFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	decoded, err := io.ReadAll(outputFile)
	require.NoError(t, err)
	require.Equal(t, original, decoded, "decoded data should match original")
}

func TestSeekTableMagic(t *testing.T) {
	// Minimal test: verify the seek table magic is at EOF
	// dm-verity requires data to be at least one block (4096 bytes)
	original := make([]byte, 4096)
	copy(original, []byte("hello world, this is test data for encoding"))

	tmpFile, err := os.CreateTemp("", "seekable-test-*.bin")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	_, err = EncodeWithDMVerity(context.Background(), bytes.NewReader(original), tmpFile, 4096, false)
	require.NoError(t, err)

	// Check last 4 bytes
	_, err = tmpFile.Seek(-4, io.SeekEnd)
	require.NoError(t, err)

	var magic uint32
	err = binary.Read(tmpFile, binary.LittleEndian, &magic)
	require.NoError(t, err)
	require.Equal(t, uint32(SeekableMagic), magic)
}

func TestInspect(t *testing.T) {
	// Create test data: 128 KB (2 chunks with 64 KB chunk size)
	original := make([]byte, 128*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}

	tmpFile, err := os.CreateTemp("", "seekable-test-*.bin")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	_, err = EncodeWithDMVerity(context.Background(), bytes.NewReader(original), tmpFile, 64*1024, false)
	require.NoError(t, err)

	_, err = tmpFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	// Inspect should not return an error
	err = Inspect(tmpFile, true)
	require.NoError(t, err)
}

func TestDMVerityMismatch(t *testing.T) {
	// Test that dm-verity verification fails when data is corrupted
	original := make([]byte, 64*1024)
	for i := range original {
		original[i] = byte(i)
	}

	tmpFile, err := os.CreateTemp("", "seekable-test-*.bin")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	result, err := EncodeWithDMVerity(context.Background(),
		bytes.NewReader(original), tmpFile, 64*1024, false)
	require.NoError(t, err)

	_, err = tmpFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	outputFile, err := os.CreateTemp("", "decoded-*.bin")
	require.NoError(t, err)
	defer os.Remove(outputFile.Name())
	defer outputFile.Close()

	// Use a wrong root digest
	wrongDigest := "0000000000000000000000000000000000000000000000000000000000000000"
	_, err = Decode(tmpFile, outputFile, result.FramesEndOffset, wrongDigest, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dm-verity verification failed")
}

func TestMultipleChunks(t *testing.T) {
	// Test with more chunks to verify seek table handles multiple frames
	original := make([]byte, 1024*1024) // 1 MB
	for i := range original {
		original[i] = byte(i % 256)
	}

	tmpFile, err := os.CreateTemp("", "seekable-test-*.bin")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Use 64KB chunks = 16 frames for 1MB
	result, err := EncodeWithDMVerity(context.Background(),
		bytes.NewReader(original), tmpFile, 64*1024, false)
	require.NoError(t, err)

	require.Equal(t, 16, result.NumFrames, "expected 16 frames for 1MB with 64KB chunks")

	_, err = tmpFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	outputFile, err := os.CreateTemp("", "decoded-*.bin")
	require.NoError(t, err)
	defer os.Remove(outputFile.Name())
	defer outputFile.Close()

	decResult, err := Decode(tmpFile, outputFile, result.FramesEndOffset, result.RootDigest, false)
	require.NoError(t, err)
	require.True(t, decResult.DMVerityValid)
	require.Equal(t, int64(len(original)), decResult.DecompressedSize)

	// Verify content
	_, err = outputFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	decoded, err := io.ReadAll(outputFile)
	require.NoError(t, err)
	require.Equal(t, original, decoded)
}

func TestRoundTripNoDMVerity(t *testing.T) {
	// Use a non-4KiB-aligned size to ensure dm-verity is truly not required.
	original := make([]byte, 100000)
	for i := range original {
		original[i] = byte(i % 251)
	}

	tmpFile, err := os.CreateTemp("", "seekable-test-nodmv-*.bin")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	result, err := Encode(context.Background(), bytes.NewReader(original), tmpFile, 64*1024, false)
	require.NoError(t, err)
	require.Equal(t, "", result.RootDigest)
	require.Equal(t, int64(0), result.DMVeritySize)

	_, err = tmpFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	outputFile, err := os.CreateTemp("", "decoded-nodmv-*.bin")
	require.NoError(t, err)
	defer os.Remove(outputFile.Name())
	defer outputFile.Close()

	decResult, err := Decode(tmpFile, outputFile, 0, "" /* expectedRootDigest */, false)
	require.NoError(t, err)
	require.Equal(t, int64(len(original)), decResult.DecompressedSize)

	_, err = outputFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	decoded, err := io.ReadAll(outputFile)
	require.NoError(t, err)
	require.Equal(t, original, decoded)
}

func TestInspectNoDMVerity(t *testing.T) {
	original := make([]byte, 12345)
	for i := range original {
		original[i] = byte(i % 97)
	}

	tmpFile, err := os.CreateTemp("", "seekable-test-inspect-nodmv-*.bin")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	_, err = Encode(context.Background(), bytes.NewReader(original), tmpFile, 1024, false)
	require.NoError(t, err)

	_, err = tmpFile.Seek(0, io.SeekStart)
	require.NoError(t, err)

	require.NoError(t, Inspect(tmpFile, false))
}

