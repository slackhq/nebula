package fec

// Arithmetic over GF(2^8) with the reducing polynomial x^8+x^4+x^3+x^2+1 (0x11d).
// Addition is XOR. Multiplication uses log/exp tables; the exp table is doubled so
// the sum of two logs never needs reducing mod 255.

const gfPoly = 0x11d

var (
	gfExp [510]byte
	gfLog [256]byte
)

func init() {
	x := 1
	for i := range 255 {
		gfExp[i] = byte(x)
		gfExp[i+255] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= gfPoly
		}
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfInv returns the multiplicative inverse of a. a must be non-zero.
func gfInv(a byte) byte {
	return gfExp[255-int(gfLog[a])]
}

// mulAdd computes dst ^= c*src element-wise. dst must be at least as long as src.
func mulAdd(dst, src []byte, c byte) {
	switch c {
	case 0:
		return
	case 1:
		for i, s := range src {
			dst[i] ^= s
		}
		return
	}

	var t [256]byte
	lc := int(gfLog[c])
	for s := 1; s < 256; s++ {
		t[s] = gfExp[int(gfLog[s])+lc]
	}
	for i, s := range src {
		dst[i] ^= t[s]
	}
}

// coefficient returns the generator matrix entry for repair symbol index row and
// data symbol index col. Repair rows are a Cauchy matrix 1/(x_row + y_col) with
// x_row = row and y_col = col: rows are always >= k and columns < k so the two
// sets are disjoint, which makes every square submatrix invertible and the
// systematic code [I; C] MDS. A row depends only on its index, never on how many
// repair symbols exist, so new repair symbols can be generated at any time.
func coefficient(row, col int) byte {
	return gfInv(byte(row) ^ byte(col))
}

// invert inverts the n x n matrix m in place with Gauss-Jordan elimination.
// It returns false if m is singular.
func invert(m [][]byte) bool {
	n := len(m)
	inv := make([][]byte, n)
	for i := range inv {
		inv[i] = make([]byte, n)
		inv[i][i] = 1
	}

	for col := range n {
		pivot := -1
		for r := col; r < n; r++ {
			if m[r][col] != 0 {
				pivot = r
				break
			}
		}
		if pivot < 0 {
			return false
		}
		m[col], m[pivot] = m[pivot], m[col]
		inv[col], inv[pivot] = inv[pivot], inv[col]

		scale := gfInv(m[col][col])
		for c := range n {
			m[col][c] = gfMul(m[col][c], scale)
			inv[col][c] = gfMul(inv[col][c], scale)
		}

		for r := 0; r < n; r++ {
			if r == col || m[r][col] == 0 {
				continue
			}
			f := m[r][col]
			for c := range n {
				m[r][c] ^= gfMul(f, m[col][c])
				inv[r][c] ^= gfMul(f, inv[col][c])
			}
		}
	}

	copy(m, inv)
	return true
}
