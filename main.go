package main

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/Nik-U/pbc"
)

type RawElement [2]byte
type RawElementSlice []RawElement

func (p RawElementSlice) Len() int {
	return len(p)
}

func (p RawElementSlice) Less(x, y int) bool {
	a := p[x]
	b := p[y]

	for i, byteVal := range a {
		if byteVal < b[i] {
			return true
		} else if byteVal > b[i] {
			return false
		}
	}
	return false
}

func (p RawElementSlice) Swap(i, j int) {
	temp := p[i]
	p[i] = p[j]
	p[j] = temp
}

type Party int

const(
	ClientParty Party = 0
	ServerParty = 1
)

type DualAPSIScheme struct {
	params *pbc.Params
	pairing *pbc.Pairing

	P *pbc.Element
	x *pbc.Element
	y *pbc.Element
	xP *pbc.Element
	yP *pbc.Element

	hash1 hash.Hash
}

func NewDualAPSIScheme() (time.Duration, DualAPSIScheme) {
	// The Setup phase generates public parameters:
	//
	//  - e : G x G -> G_T
	//  - PK_J = (P, xP, yP)
	//  - SK_J = (x, y)
	//
	startSetup := time.Now()

	params := pbc.GenerateA(160, 512)
	pairing := params.NewPairing()

	P := pairing.NewG1()
	xP := pairing.NewG1()
	yP := pairing.NewG1()
	x := pairing.NewZr()
	y := pairing.NewZr()

	P.Rand()
	x.Rand()
	y.Rand()
	xP.MulZn(P, x)
	yP.MulZn(P, y)

	setupTime := time.Since(startSetup)
	return setupTime, DualAPSIScheme{params, pairing, P, x, y, xP, yP, sha256.New()}
}

func (scheme *DualAPSIScheme) Authorize(elt RawElement, party Party) (time.Duration, *pbc.Element) {
	var secretKey *pbc.Element
	switch party {
	case ClientParty:
		secretKey = scheme.x
	case ServerParty:
		secretKey = scheme.y
	}

	startTime := time.Now()

	// Signature = xH(elt)
	H_elt := scheme.pairing.NewG1()
	xH_elt := scheme.pairing.NewG1()

	hashed := sha256.Sum256(elt[:])
	H_elt.SetFromHash(hashed[:])
	xH_elt.MulZn(H_elt, secretKey)

	totalTime := time.Since(startTime)
	return totalTime, xH_elt
}

func (scheme *DualAPSIScheme) Interaction(
		clientSet RawElementSlice, clientSignatures []*pbc.Element,
		serverSet RawElementSlice, serverSignatures []*pbc.Element) (time.Duration, RawElementSlice) {

	startTime := time.Now()

	// Step 1: C -> S: {rxP}
	r := scheme.pairing.NewZr()
	rxP := scheme.pairing.NewG1()
	ryP := scheme.pairing.NewG1()

	r.Rand()
	rxP.MulZn(scheme.xP, r)
	ryP.MulZn(scheme.yP, r)

	// Step 2: S -> C: {t_0, ..., t_{n-1}}
	// where t_j = e(H(s_j)^y, P^xr_c)
	serverHashes := make(map[[32]byte]bool)
	e_sig_rxP := scheme.pairing.NewGT()
	for _, serverSignature := range serverSignatures {
		// Recall that serverSignature = H(c_i)^y.
		e_sig_rxP.Pair(serverSignature, rxP)

		hashed := sha256.Sum256(e_sig_rxP.Bytes())
		serverHashes[hashed] = true
	}

	// Step 3: C computes u_i = e(H(c_i)^x, P^y)^r_c
	var intersection RawElementSlice
	e_sig_ryP := scheme.pairing.NewGT()
	for i, clientSignature := range clientSignatures {
		// Recall that clientSignature = H(c_i)^x.
		e_sig_ryP.Pair(clientSignature, ryP)

		hashed := sha256.Sum256(e_sig_ryP.Bytes())
		_, serverHas := serverHashes[hashed]
		if serverHas {
			intersection = append(intersection, clientSet[i])
		}
	}

	totalTime := time.Since(startTime)
	return totalTime, intersection
}

func (scheme *DualAPSIScheme) ThreadedInteraction(
		clientSet RawElementSlice, clientSignatures []*pbc.Element,
		serverSet RawElementSlice, serverSignatures []*pbc.Element) (time.Duration, RawElementSlice) {

	startTime := time.Now()

	// Step 1: C -> S: {rxP}
	r := scheme.pairing.NewZr()
	rxP := scheme.pairing.NewG1()
	ryP := scheme.pairing.NewG1()

	r.Rand()
	rxP.MulZn(scheme.xP, r)
	ryP.MulZn(scheme.yP, r)

	// Step 2: S -> C: {t_0, ..., t_{n-1}}
	// where t_j = e(H(s_j)^y, P^xr_c)
	serverHashes := make(map[[32]byte]bool)
	var serverWG sync.WaitGroup
	var serverLock sync.RWMutex
	serverWG.Add(len(serverSignatures))
	for _, serverSignature := range serverSignatures {
		go func(signature *pbc.Element) {
			// Recall that serverSignature = H(c_i)^y.
			e_sig_rxP := scheme.pairing.NewGT()
			e_sig_rxP.Pair(signature, rxP)

			hashed := sha256.Sum256(e_sig_rxP.Bytes())

			serverLock.Lock()
			serverHashes[hashed] = true
			serverLock.Unlock()

			serverWG.Done()
		}(serverSignature)
	}
	serverWG.Wait()

	// Step 3: C computes u_i = e(H(c_i)^x, P^y)^r_c
	var intersection RawElementSlice
	var clientWG sync.WaitGroup
	var clientLock sync.RWMutex
	clientWG.Add(len(clientSignatures))
	for i, clientSignature := range clientSignatures {
		go func(signature *pbc.Element, index int) {
			e_sig_ryP := scheme.pairing.NewGT()
			e_sig_ryP.Pair(signature, ryP)

			hashed := sha256.Sum256(e_sig_ryP.Bytes())

			serverLock.RLock()
			_, serverHas := serverHashes[hashed]
			serverLock.RUnlock()

			if serverHas {
				clientLock.Lock()
				intersection = append(intersection, clientSet[index])
				clientLock.Unlock()
			}

			clientWG.Done()
		}(clientSignature, i)
	}
	clientWG.Wait()

	totalTime := time.Since(startTime)
	return totalTime, intersection
}

func BenchmarkDualPSIInteraction(isDebug bool, clientCardinality int, serverCardinality int) {
	setupTime, scheme := NewDualAPSIScheme()
	fmt.Println("Setup time:", setupTime)

	clientSet := generateRandomSet(clientCardinality)
	serverSet := generateRandomSet(serverCardinality)

	realTime, realIntersection := findRealIntersection(clientSet, serverSet)
	sort.Sort(realIntersection)
	fmt.Println("Real intersection: ", realIntersection)
	fmt.Println("Real time:", realTime)

	clientSigningTime, clientSignatures :=
		scheme.generateSignaturesOnSet(clientSet, ClientParty)
	serverSigningTime, serverSignatures :=
		scheme.generateSignaturesOnSet(serverSet, ServerParty)
	fmt.Println("Client signing time (avg):", clientSigningTime / time.Duration(clientCardinality))
	fmt.Println("Server signing time (avg):", serverSigningTime / time.Duration(serverCardinality))

	interactionTime, protocolIntersection := scheme.Interaction(clientSet, clientSignatures, serverSet, serverSignatures)
	sort.Sort(protocolIntersection)
	fmt.Println("Interaction time:", interactionTime)
	fmt.Println("Protocol intersection: ", protocolIntersection)

	interactionTime, protocolIntersection = scheme.ThreadedInteraction(clientSet, clientSignatures, serverSet, serverSignatures)
	sort.Sort(protocolIntersection)
	fmt.Println("Threaded interaction time:", interactionTime)
	fmt.Println("Protocol threaded intersection: ", protocolIntersection)

	// Verify equality:
	isEqual := sameRawElementSlice(realIntersection, protocolIntersection)
	fmt.Println("Correct?", isEqual)
}

func findRealIntersection(clientSet RawElementSlice, serverSet RawElementSlice) (time.Duration, RawElementSlice) {
	startTime := time.Now()

	lookupTable := make(map[RawElement]bool)
	for _, element := range clientSet {
		lookupTable[element] = true
	}

	var intersection RawElementSlice
	for _, element := range serverSet {
		_, isInLookup := lookupTable[element]
		if isInLookup {
			intersection = append(intersection, element)
		}
	}

	totalTime := time.Since(startTime)
	return totalTime, intersection
}

func generateRandomSet(size int) RawElementSlice {
	result := make(RawElementSlice, size)
	for i := 0; i < size; i++ {
		rand.Read(result[i][:])
	}
	return removeDuplicateValues(result)
}

func removeDuplicateValues(elementSlice RawElementSlice) RawElementSlice {
    keys := make(map[RawElement]bool)
    list := RawElementSlice{}

    // If the key(values of the slice) is not equal
    // to the already present value in new slice (list)
    // then we append it. else we jump on another element.
    for _, entry := range elementSlice {
        if _, value := keys[entry]; !value {
            keys[entry] = true
            list = append(list, entry)
        }
    }
    return list
}


func sameRawElementSlice(x, y []RawElement) bool {
    if len(x) != len(y) {
        return false
    }
    // create a map of RawElement -> int
    diff := make(map[RawElement]int, len(x))
    for _, _x := range x {
        // 0 value for int is 0, so just increment a counter for the RawElement
        diff[_x]++
    }
    for _, _y := range y {
        // If the RawElement _y is not in diff bail out early
        if _, ok := diff[_y]; !ok {
            return false
        }
        diff[_y] -= 1
        if diff[_y] == 0 {
            delete(diff, _y)
        }
    }
    if len(diff) == 0 {
        return true
    }
    return false
}


func (scheme *DualAPSIScheme) generateSignaturesOnSet(elements []RawElement, party Party) (time.Duration, []*pbc.Element) {
	var totalTime, signingTime time.Duration
	signatures := make([]*pbc.Element, len(elements))
	for i, element := range elements {
		signingTime, signatures[i] = scheme.Authorize(element, party)
		totalTime += signingTime
	}
	return totalTime, signatures
}

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

	fmt.Println("Testing Dual-APSI...")
	BenchmarkDualPSIInteraction(true, 1000, 1000)

	fmt.Println("Testing Joux Benchmark...")
	BenchmarkJouxKeyExchange(false)

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
