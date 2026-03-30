package util

import (
	"bufio"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func scanAll(t *testing.T, input string) ([]string, error) {
	t.Helper()
	scanner := bufio.NewScanner(strings.NewReader(input))
	scanner.Split(SplitPEM)
	var blocks []string
	for scanner.Scan() {
		blocks = append(blocks, scanner.Text())
	}
	return blocks, scanner.Err()
}

func TestSplitPEM_Single(t *testing.T) {
	input := "-----BEGIN TEST-----\ndata\n-----END TEST-----\n"
	blocks, err := scanAll(t, input)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, input, blocks[0])
}

func TestSplitPEM_Multiple(t *testing.T) {
	block1 := "-----BEGIN TEST-----\naaa\n-----END TEST-----\n"
	block2 := "-----BEGIN TEST-----\nbbb\n-----END TEST-----\n"
	blocks, err := scanAll(t, block1+block2)
	require.NoError(t, err)
	require.Len(t, blocks, 2)
	require.Equal(t, block1, blocks[0])
	require.Equal(t, block2, blocks[1])
}

func TestSplitPEM_CommentsAndWhitespaceBetweenBlocks(t *testing.T) {
	input := "# comment\n\n-----BEGIN TEST-----\naaa\n-----END TEST-----\n\n# another comment\n\n-----BEGIN TEST-----\nbbb\n-----END TEST-----\n"
	blocks, err := scanAll(t, input)
	require.NoError(t, err)
	require.Len(t, blocks, 2)
}

func TestSplitPEM_Empty(t *testing.T) {
	blocks, err := scanAll(t, "")
	require.NoError(t, err)
	require.Empty(t, blocks)
}

func TestSplitPEM_WhitespaceOnly(t *testing.T) {
	blocks, err := scanAll(t, "  \n\t\n  ")
	require.NoError(t, err)
	require.Empty(t, blocks)
}

func TestSplitPEM_TrailingGarbage(t *testing.T) {
	input := "-----BEGIN TEST-----\ndata\n-----END TEST-----\ngarbage"
	blocks, err := scanAll(t, input)
	require.ErrorIs(t, err, ErrTruncatedPEMBlock)
	require.Len(t, blocks, 1)
}

func TestSplitPEM_TruncatedBlock(t *testing.T) {
	input := "-----BEGIN TEST-----\npartial data with no end"
	_, err := scanAll(t, input)
	require.ErrorIs(t, err, ErrTruncatedPEMBlock)
}

func TestSplitPEM_NoEndNewline(t *testing.T) {
	input := "-----BEGIN TEST-----\ndata\n-----END TEST-----"
	blocks, err := scanAll(t, input)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	require.Equal(t, input, blocks[0])
}

func TestSplitPEM_GarbageOnly(t *testing.T) {
	_, err := scanAll(t, "this is not PEM data")
	require.ErrorIs(t, err, ErrTruncatedPEMBlock)
}
