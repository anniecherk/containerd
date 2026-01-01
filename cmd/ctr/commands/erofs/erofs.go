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

// Package erofs provides CLI commands for working with seekable EROFS blobs.
package erofs

import (
	"context"
	"fmt"
	"os"

	"github.com/containerd/containerd/v2/internal/seekablezstd"
	"github.com/urfave/cli/v2"
)

// Command is the ctr erofs subcommand
var Command = &cli.Command{
	Name:  "erofs",
	Usage: "Manage seekable EROFS blobs",
	Description: `Commands for working with seekable zstd compressed EROFS blobs.

These blobs use one of the formats:
- [zstd frames][seek table @ EOF] (default)
- [zstd frames][dm-verity data][seek table @ EOF] (when --dm-verity=true)

The seek table at EOF follows the standard zstd seekable format,
enabling random access decompression for lazy loading.
`,
	Subcommands: []*cli.Command{
		inspectCommand,
		decodeCommand,
		encodeCommand,
	},
}

var inspectCommand = &cli.Command{
	Name:      "inspect",
	Usage:     "Inspect a seekable EROFS blob",
	ArgsUsage: "<blob_path>",
	Description: `Print detailed information about a seekable zstd EROFS blob.

This validates the seekable format and shows:
- File size
- Seek table location and frame count
- Checksum flag status
`,
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "verbose",
			Aliases: []string{"v"},
			Usage:   "Print detailed frame information",
		},
	},
	Action: func(cliContext *cli.Context) error {
		blobPath := cliContext.Args().First()
		if blobPath == "" {
			return fmt.Errorf("blob path required")
		}

		f, err := os.Open(blobPath)
		if err != nil {
			return fmt.Errorf("open blob: %w", err)
		}
		defer f.Close()

		return seekablezstd.Inspect(f, cliContext.Bool("verbose"))
	},
}

var decodeCommand = &cli.Command{
	Name:      "decode",
	Usage:     "Decode a seekable EROFS blob",
	ArgsUsage: "<blob_path> <output_path>",
	Description: `Decompress a seekable zstd EROFS blob and optionally verify dm-verity.

Example:
  ctr erofs decode --verbose --dmverity-root-digest=abc123... blob.erofs.zst decoded.erofs
`,
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "verbose",
			Aliases: []string{"v"},
			Usage:   "Print detailed decoding progress",
		},
		&cli.Int64Flag{
			Name:    "dmverity-offset",
			Aliases: []string{"frames-end"},
			Usage:   "Byte offset where dm-verity data begins (for info only; equals end-of-frames when dm-verity is present)",
		},
		&cli.StringFlag{
			Name:    "dmverity-root-digest",
			Aliases: []string{"root-digest"},
			Usage:   "Expected dm-verity root digest for verification",
		},
	},
	Action: func(cliContext *cli.Context) error {
		blobPath := cliContext.Args().Get(0)
		outputPath := cliContext.Args().Get(1)

		if blobPath == "" || outputPath == "" {
			return fmt.Errorf("blob path and output path required")
		}

		// Open input
		input, err := os.Open(blobPath)
		if err != nil {
			return fmt.Errorf("open input: %w", err)
		}
		defer input.Close()

		// Create output
		output, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer output.Close()

		dmverityOffset := cliContext.Int64("dmverity-offset")
		rootDigest := cliContext.String("dmverity-root-digest")
		verbose := cliContext.Bool("verbose")

		result, err := seekablezstd.Decode(input, output, dmverityOffset, rootDigest, verbose)
		if err != nil {
			return err
		}

		fmt.Printf("Decoded %d bytes to %s\n", result.DecompressedSize, outputPath)
		if rootDigest != "" {
			if result.DMVerityValid {
				fmt.Printf("DM-verity: VALID\n")
			} else {
				fmt.Printf("DM-verity: MISMATCH (expected %s, got %s)\n", rootDigest, result.ActualRootDigest)
			}
		}

		return nil
	},
}

var encodeCommand = &cli.Command{
	Name:      "encode",
	Usage:     "Encode data to seekable EROFS format",
	ArgsUsage: "<input_path> <output_path>",
	Description: `Compress data using seekable zstd, optionally including dm-verity.

Output format (default):   [zstd frames][seek table @ EOF]
Output format (dm-verity): [zstd frames][dm-verity data][seek table @ EOF]

Example:
  ctr erofs encode --verbose --chunk-size=65536 input.erofs output.erofs.zst
  ctr erofs encode --dm-verity input.erofs output.erofs.zst
`,
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "verbose",
			Aliases: []string{"v"},
			Usage:   "Print detailed encoding progress",
		},
		&cli.BoolFlag{
			Name:  "dm-verity",
			Usage: "Include dm-verity superblock+tree between frames and seek table",
			Value: false,
		},
		&cli.IntFlag{
			Name:  "chunk-size",
			Usage: "Chunk size in bytes for compression",
			Value: seekablezstd.DefaultChunkSize,
		},
	},
	Action: func(cliContext *cli.Context) error {
		inputPath := cliContext.Args().Get(0)
		outputPath := cliContext.Args().Get(1)

		if inputPath == "" || outputPath == "" {
			return fmt.Errorf("input path and output path required")
		}

		// Open input
		input, err := os.Open(inputPath)
		if err != nil {
			return fmt.Errorf("open input: %w", err)
		}
		defer input.Close()

		// Create output
		output, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		defer output.Close()

		chunkSize := cliContext.Int("chunk-size")
		verbose := cliContext.Bool("verbose")
		includeDMVerity := cliContext.Bool("dm-verity")

		var result *seekablezstd.EncodeResult
		if includeDMVerity {
			result, err = seekablezstd.EncodeWithDMVerity(context.Background(),
				input, output, chunkSize, verbose)
		} else {
			result, err = seekablezstd.Encode(context.Background(),
				input, output, chunkSize, verbose)
		}
		if err != nil {
			return err
		}

		fmt.Printf("Encoded %d -> %d bytes (%.1f%%)\n",
			result.UncompressedSize, result.TotalSize,
			float64(result.TotalSize)/float64(result.UncompressedSize)*100)
		fmt.Printf("Frames: %d, dmverity-offset: %d\n", result.NumFrames, result.FramesEndOffset)
		if includeDMVerity {
			fmt.Printf("DM-verity root digest: %s\n", result.RootDigest)
		} else {
			fmt.Printf("DM-verity: not included\n")
		}

		return nil
	},
}

