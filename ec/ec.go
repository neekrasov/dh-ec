package ec

import (
	"math/big"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

type (
	Point struct {
		X *big.Int
		Y *big.Int
	}

	EC struct {
		a, b, p, n *big.Int
		g          *Point
	}
)

func Secp256k1() *EC {
	p, _ := ParseHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	a, _ := ParseHex("0000000000000000000000000000000000000000000000000000000000000000")
	b, _ := ParseHex("0000000000000000000000000000000000000000000000000000000000000007")
	n, _ := ParseHex("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	gx, _ := ParseHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	gy, _ := ParseHex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

	return &EC{a: a, b: b, p: p, n: n, g: &Point{X: gx, Y: gy}}
}

func (ec *EC) Sum(a, b *Point) *Point {
	// Slope = (By - Ay)/(Bx - Ax) mod p

	if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0 {
		return ec.Double(a) // if a == b.
	}

	// By - Ay mod p
	slope := new(big.Int).Sub(b.Y, a.Y)
	slope.Mod(slope, ec.p)

	// Bx - Ax mod p
	inv := new(big.Int).Sub(b.X, a.X)
	inv.ModInverse(inv, ec.p)

	// (By - Ay)/(Bx - Ax) mod p
	slope.Mul(slope, inv)
	slope.Mod(slope, ec.p)

	// Cx = slope^2 - Ax - Bx mod p
	Cx := new(big.Int).Mul(slope, slope)
	Cx.Sub(Cx, a.X)
	Cx.Sub(Cx, b.X)
	Cx.Mod(Cx, ec.p)

	// Cy = slope * (Ax - Rx) - Ay mod p
	Cy := new(big.Int).Sub(a.X, Cx)
	Cy.Mul(slope, Cy)
	Cy.Sub(Cy, a.Y)
	Cy.Mod(Cy, ec.p)

	return &Point{X: Cx, Y: Cy}
}

func (ec *EC) Double(p *Point) *Point {
	// Slope = (3 * Ax^2 + a)/(2 * Ay) mod p

	slope := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(p.X, p.X)) // 3 * Ax^2
	slope.Add(slope, ec.a)                                               // 3 * Ax^2 + a
	slope.Mod(slope, ec.p)                                               // 3 * Ax^2 + a mod p

	inv := new(big.Int).Mul(big.NewInt(2), p.Y) // 2 * Ay
	inv.ModInverse(inv, ec.p)                   // 2 * Ay mod p

	slope.Mul(slope, inv)  // (3 * Ax^2 + a)/(2 * Ay)
	slope.Mod(slope, ec.p) // (3 * Ax^2 + a)/(2 * Ay) mod p

	//Cx = slope^2 - 2 * Ax mod p
	Cx := new(big.Int).Mul(slope, slope)
	Cx.Sub(Cx, new(big.Int).Mul(big.NewInt(2), p.X))
	Cx.Mod(Cx, ec.p)

	//Cy = slope * (Ax - Rx) - Ay mod p
	Cy := new(big.Int).Sub(p.X, Cx)
	Cy.Mul(slope, Cy)
	Cy.Sub(Cy, p.Y)
	Cy.Mod(Cy, ec.p)

	return &Point{X: Cx, Y: Cy}
}

// Doubling and adding algorithm
func (ec *EC) ScalarMult(p *Point, k *big.Int) *Point {
	res := &Point{new(big.Int), new(big.Int)}                   // переменная результата
	tmp := &Point{new(big.Int).Set(p.X), new(big.Int).Set(p.Y)} // храним изначальную точку

	for i := k.BitLen() - 1; i >= 0; i-- {
		if res.X.Sign() != 0 || res.Y.Sign() != 0 {
			res = ec.Double(res)
		}

		if k.Bit(i) == 1 {
			// т.к работаем в поле, и у точки есть порядок, она может занулиться
			// в данном случае проставляем её дефолтное значение и алгоритм продолжается.
			if res.X.Sign() == 0 && res.Y.Sign() == 0 {
				res = &Point{new(big.Int).Set(tmp.X), new(big.Int).Set(tmp.Y)}
			} else {
				res = ec.Sum(res, tmp)
			}
		}
	}

	return res
}

func (ec *EC) PubKey(privKey *big.Int) *Point {
	return ec.ScalarMult(ec.g, privKey)
}

func (ec *EC) SecretKey(number *big.Int, publicKey *Point) *Point {
	return ec.ScalarMult(publicKey, number)
}

func ParseHex(hex string) (*big.Int, bool) {
	return new(big.Int).SetString(strings.ReplaceAll(hex, ":", ""), 16)
}

func RandNum(bits int) (*big.Int, error) {
	output, err := exec.Command("openssl", "rand", "-hex", strconv.Itoa(bits)).Output()
	if err != nil {
		return nil, errors.Wrap(err, "generating random number failed")
	}

	val, _ := new(big.Int).SetString(strings.TrimSpace(string(output)), 16)
	return val, nil
}
