package main

import (
	"fmt"
	"time"
	"github.com/Nik-U/pbc"
)

// This example program simulates a Joux key exchange. Based on the C-based
// implementation from https://github.com/blynn/pbc/blob/master/example/joux.c.
func BenchmarkJouxKeyExchange(isDebug bool) (setupTime time.Duration, onlineTime time.Duration) {
	startSetup := time.Now()

	// Prime r must have 160 bits, and prime q must have 512 bits. These are
	// suggested parameters from https://crypto.stanford.edu/pbc/manual/ch05s01.html,
	// which states that "To be secure, generic discrete log algorithms must be
	// infeasible in groups of order r, and finite field discrete log algorithms
	// must be infeasible in finite fields of order q^2, e.g. rbits = 160,
	// qbits = 512."
	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()
	setupTime = time.Since(startSetup)

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

	// Actual protocol starts.

	startOnline := time.Now()

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

	onlineTime = time.Since(startOnline)

	if isDebug {
		fmt.Println("Done! Time elapsed: ")
		fmt.Println("   (setup) ", setupTime)
		fmt.Println("  (online) ", onlineTime)

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

	return
}

func main() {
	pbc.SetLogging(false)

	fmt.Println("Testing Joux Benchmark...")
	BenchmarkJouxKeyExchange(true)

	totalRuns := 1000
	fmt.Println("Running full benchmark with", totalRuns, "runs...")
	var totalSetup time.Duration
	var totalOnline time.Duration

	for i := 1; i <= totalRuns; i++ {
	    setupTime, onlineTime := BenchmarkJouxKeyExchange(false)
	    totalSetup += setupTime
	    totalOnline += onlineTime
	}

	fmt.Println("Done! Average time elapsed: ")
	fmt.Println("   (setup) ", totalSetup / 1000)
	fmt.Println("  (online) ", totalOnline / 1000)
}
