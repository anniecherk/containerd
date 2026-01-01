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
	"fmt"
	"io"
)

// roundUpToBlock rounds size up to the nearest multiple of blockSize.
func roundUpToBlock(size int64, blockSize int64) int64 {
	if blockSize <= 0 {
		// Should never happen with our constants; keep it safe.
		return size
	}
	rem := size % blockSize
	if rem == 0 {
		return size
	}
	return size + (blockSize - rem)
}

// zeroReader yields n zero bytes without allocating.
type zeroReader struct {
	n int64
}

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	for i := range p {
		p[i] = 0
	}
	z.n -= int64(len(p))
	if z.n == 0 {
		return len(p), io.EOF
	}
	return len(p), nil
}

// writeFull writes all bytes in p to w, returning the total bytes written.
// This avoids subtle corruption if an io.Writer performs a short write.
func writeFull(w io.Writer, p []byte) (int, error) {
	total := 0
	for total < len(p) {
		n, err := w.Write(p[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, fmt.Errorf("short write: wrote 0 bytes with no error")
		}
	}
	return total, nil
}

