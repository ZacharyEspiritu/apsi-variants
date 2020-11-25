package main

import (
	"fmt"
	"time"
	"github.com/Nik-U/pbc"
)

// This example program simulates a Joux key exchange. Based on the C-based
// implementation from https://github.com/blynn/pbc/blob/master/example/joux.c.

func main() {
	pbc.SetLogging(true)
	fmt.Println("hello world")

	// Prime r must have 160 bits, and prime q must have 512 bits. These are
	// suggested parameters from https://crypto.stanford.edu/pbc/manual/ch05s01.html,
	// which states that "To be secure, generic discrete log algorithms must be
	// infeasible in groups of order r, and finite field discrete log algorithms
	// must be infeasible in finite fields of order q^2, e.g. rbits = 160,
	// qbits = 512."
	params := pbc.GenerateA(160, 512)

	fmt.Println(params.String())

	pairing := params.NewPairing()
	fmt.Println(pairing.IsSymmetric())

	P := pairing.NewG1()
	aP := pairing.NewG1()
	bP := pairing.NewG1()
	cP := pairing.NewG1()

	a := pairing.NewZr()
	b := pairing.NewZr()
	c := pairing.NewZr()

	e_bP_cP := pairing.NewGT()
	e_aP_cP := pairing.NewGT()
	e_aP_bP := pairing.NewGT()

	keyA := pairing.NewGT()
	keyB := pairing.NewGT()
	keyC := pairing.NewGT()

	fmt.Println("Starting Joux key exchange...")
	start := time.Now()

	P.Rand()
	a.Rand()
	b.Rand()
	c.Rand()

	aP.MulZn(P, a)
	bP.MulZn(P, b)
	cP.MulZn(P, c)

	// e(bP, cP)^a
	e_bP_cP.Pair(bP, cP)
	keyA.PowZn(e_bP_cP, a)

	// e(aP, cP)^b
	e_aP_cP.Pair(aP, cP)
	keyB.PowZn(e_aP_cP, b)

	// e(aP, bP)^c
	e_aP_bP.Pair(aP, bP)
	keyC.PowZn(e_aP_bP, c)

	duration := time.Since(start)
	fmt.Println("Done! Time elapsed: ", duration)

	fmt.Println("aP = ", aP)
	fmt.Println("bP = ", bP)
	fmt.Println("cP = ", cP)

	fmt.Println("Key A = ", keyA)
	fmt.Println("Key B = ", keyB)
	fmt.Println("Key C = ", keyC)

	isKeysMatch := keyA.Equals(keyB) && keyA.Equals(keyC)
	if isKeysMatch {
		fmt.Println("All keys match!")
	} else {
		fmt.Println("Keys do not match. Something went wrong!")
	}
}
