package main

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math/rand"
	"os"
	"log"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"flag"
	"math"

	"github.com/Nik-U/pbc"
	"github.com/olekukonko/tablewriter"
	// "github.com/cornelk/hashmap"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

type RawElement [4]byte
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

	// Step 1: S -> C: {t_0, ..., t_{n-1}}
	// where t_j = e(H(s_j)^y, P^xr_c)
	r := scheme.pairing.NewZr()
	rxP := scheme.pairing.NewG1()
	ryP := scheme.pairing.NewG1()

	r.Rand()
	rxP.MulZn(scheme.xP, r)
	ryP.MulZn(scheme.yP, r)

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

	// Step 1: S -> C: {t_0, ..., t_{n-1}}
	// where t_j = e(H(s_j)^y, P^xr_c)
	r := scheme.pairing.NewZr()
	rxP := scheme.pairing.NewG1()
	ryP := scheme.pairing.NewG1()

	r.Rand()
	rxP.MulZn(scheme.xP, r)
	ryP.MulZn(scheme.yP, r)

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

			_, serverHas := serverHashes[hashed]
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

func (scheme *DualAPSIScheme) SmarterThreadedInteraction(
		clientSet RawElementSlice, clientSignatures []*pbc.Element,
		serverSet RawElementSlice, serverSignatures []*pbc.Element,
		numThreads int) (time.Duration, RawElementSlice) {

	startTime := time.Now()

	// Step 1: S -> C: {t_0, ..., t_{n-1}}
	// where t_j = e(H(s_j)^y, P^xr_c)
	r := scheme.pairing.NewZr()
	rxP := scheme.pairing.NewG1()
	ryP := scheme.pairing.NewG1()

	r.Rand()
	rxP.MulZn(scheme.xP, r)
	ryP.MulZn(scheme.yP, r)


	serverHashes := make(map[[32]byte]bool)
	var serverWG sync.WaitGroup
	var serverLock sync.RWMutex

	serverChan := make(chan *pbc.Element, len(serverSignatures))
	for _, v := range serverSignatures {
		serverChan <- v
	}
	close(serverChan)

	serverWG.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func() {
			e_sig_rxP := scheme.pairing.NewGT()

			for signature := range serverChan {
				// Recall that serverSignature = H(c_i)^y.
				e_sig_rxP.Pair(signature, rxP)
				hashed := sha256.Sum256(e_sig_rxP.Bytes())

				serverLock.Lock()
				serverHashes[hashed] = true
				serverLock.Unlock()
			}

			serverWG.Done()
		}()
	}
	serverWG.Wait()

	// Step 3: C computes u_i = e(H(c_i)^x, P^y)^r_c

	clientChan := make(chan *pbc.Element, len(clientSignatures))
	for _, v := range clientSignatures {
		clientChan <- v
	}
	close(clientChan)

	var intersection RawElementSlice
	var clientWG sync.WaitGroup
	var clientLock sync.RWMutex
	clientWG.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func() {
			e_sig_ryP := scheme.pairing.NewGT()

			for signature := range clientChan {
				e_sig_ryP.Pair(signature, ryP)

				hashed := sha256.Sum256(e_sig_ryP.Bytes())

				_, serverHas := serverHashes[hashed]
				if serverHas {
					clientLock.Lock()
					intersection = append(intersection, clientSet[0])  // TODO: make this actually append correct element, just doing this for now to get a sense of the append time
					clientLock.Unlock()
				}
			}

			clientWG.Done()
		}()
	}
	clientWG.Wait()

	totalTime := time.Since(startTime)
	return totalTime, intersection
}

func (scheme *DualAPSIScheme) AtomicsThreadedInteraction(
		clientSet RawElementSlice, clientSignatures []*pbc.Element,
		serverSet RawElementSlice, serverSignatures []*pbc.Element,
		numThreads int) (time.Duration, RawElementSlice) {

	startTime := time.Now()

	// Step 1: S -> C: {t_0, ..., t_{n-1}}
	// where t_j = e(H(s_j)^y, P^xr_c)
	r := scheme.pairing.NewZr()
	rxP := scheme.pairing.NewG1()
	ryP := scheme.pairing.NewG1()

	r.Rand()
	rxP.MulZn(scheme.xP, r)
	ryP.MulZn(scheme.yP, r)

	serverHashes := make(map[[32]byte]bool)
	var serverWG sync.WaitGroup
	var serverLock sync.RWMutex

	var serverNextIndex uint64  // serverNextIndex = 0
	serverStopIndex := uint64(len(serverSignatures))

	serverWG.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func() {
			e_sig_rxP := scheme.pairing.NewGT()

			for {
				index := atomic.AddUint64(&serverNextIndex, 1) - 1
				if index >= serverStopIndex {
					break
				}

				// Recall that serverSignature = H(c_i)^y.
				e_sig_rxP.Pair(serverSignatures[index], rxP)
				hashed := sha256.Sum256(e_sig_rxP.Bytes())

				serverLock.Lock()
				serverHashes[hashed] = true
				serverLock.Unlock()
			}

			serverWG.Done()
		}()
	}
	serverWG.Wait()

	// Step 3: C computes u_i = e(H(c_i)^x, P^y)^r_c

	var clientNextIndex uint64  // clientNextIndex = 0
	clientStopIndex := uint64(len(clientSignatures))

	var intersection RawElementSlice
	var clientWG sync.WaitGroup
	var clientLock sync.RWMutex

	clientWG.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func() {
			e_sig_ryP := scheme.pairing.NewGT()

			for {
				index := atomic.AddUint64(&clientNextIndex, 1) - 1
				if index >= clientStopIndex {
					break
				}

				e_sig_ryP.Pair(clientSignatures[index], ryP)
				hashed := sha256.Sum256(e_sig_ryP.Bytes())

				_, serverHas := serverHashes[hashed]
				if serverHas {
					clientLock.Lock()
					intersection = append(intersection, clientSet[0])  // TODO: make this actually append correct element, just doing this for now to get a sense of the append time
					clientLock.Unlock()
				}
			}

			clientWG.Done()
		}()
	}
	clientWG.Wait()

	totalTime := time.Since(startTime)
	return totalTime, intersection
}

func (scheme *DualAPSIScheme) DivisionThreadedInteraction(
		clientSet RawElementSlice, clientSignatures []*pbc.Element,
		serverSet RawElementSlice, serverSignatures []*pbc.Element,
		numThreads int) (time.Duration, RawElementSlice) {

	startTime := time.Now()

	// Step 1: S -> C: {t_0, ..., t_{n-1}}
	// where t_j = e(H(s_j)^y, P^xr_c)
	r := scheme.pairing.NewZr()
	rxP := scheme.pairing.NewG1()
	ryP := scheme.pairing.NewG1()

	r.Rand()
	rxP.MulZn(scheme.xP, r)
	ryP.MulZn(scheme.yP, r)

	serverHashes := make(map[[32]byte]bool)
	var serverWG sync.WaitGroup
	var serverLock sync.RWMutex

	numServerElts := len(serverSignatures)
	numPerServerThread := float64(numServerElts) / float64(numThreads)

	serverWG.Add(numThreads)
	for threadNum := 0; threadNum < numThreads; threadNum++ {
		go func(threadNumber int) {
			// Recall that serverSignature = H(c_i)^y.
			e_sig_rxP := scheme.pairing.NewGT()

			start := int(math.Ceil(numPerServerThread * float64(threadNumber)))
			end := int(math.Ceil(float64(start) + numPerServerThread))
			if end > numServerElts {
				end = numServerElts
			}

			for i := start; i < end; i++ {
				e_sig_rxP.Pair(serverSignatures[i], rxP)
				hashed := sha256.Sum256(e_sig_rxP.Bytes())

				serverLock.Lock()
				serverHashes[hashed] = true
				serverLock.Unlock()
			}

			serverWG.Done()
		}(threadNum)
	}
	serverWG.Wait()

	// Step 3: C computes u_i = e(H(c_i)^x, P^y)^r_c
	var intersection RawElementSlice
	var clientWG sync.WaitGroup
	var clientLock sync.RWMutex

	numClientElts := len(clientSignatures)
	numPerClientThread := float64(numClientElts) / float64(numThreads)

	clientWG.Add(numThreads)
	for threadNum := 0; threadNum < numThreads; threadNum++ {
		go func(threadNumber int) {
			e_sig_ryP := scheme.pairing.NewGT()

			start := int(math.Ceil(numPerClientThread * float64(threadNumber)))
			end := int(math.Ceil(float64(start) + numPerClientThread))
			if end > numClientElts {
				end = numClientElts
			}

			for i := start; i < end; i++ {
				e_sig_ryP.Pair(clientSignatures[i], ryP)
				hashed := sha256.Sum256(e_sig_ryP.Bytes())

				_, serverHas := serverHashes[hashed]
				if serverHas {
					clientLock.Lock()
					intersection = append(intersection, clientSet[i])
					clientLock.Unlock()
				}
			}

			clientWG.Done()
		}(threadNum)
	}
	clientWG.Wait()

	totalTime := time.Since(startTime)
	return totalTime, intersection
}

func (scheme *DualAPSIScheme) PrecomputeThreadedInteraction(
		clientSet RawElementSlice, clientSignatures []*pbc.Element,
		serverSet RawElementSlice, serverSignatures []*pbc.Element) (time.Duration, RawElementSlice) {

	// Precomputation phase.
	// Server precomputes e(H(s_j)^y, P^x) (missing r)
	var pairedSignatures []*pbc.Element
	var pairedSignaturesLock sync.RWMutex
	var pairedSignaturesWG sync.WaitGroup
	pairedSignaturesWG.Add(len(serverSignatures))
	for _, serverSignature := range serverSignatures {
		go func(signature *pbc.Element) {
			e_sig_xP := scheme.pairing.NewGT()
			e_sig_xP.Pair(signature, scheme.xP)

			pairedSignaturesLock.Lock()
			pairedSignatures = append(pairedSignatures, e_sig_xP)
			pairedSignaturesLock.Unlock()

			pairedSignaturesWG.Done()
		}(serverSignature)
	}
	pairedSignaturesWG.Wait()

	// Online phase.

	startTime := time.Now()

	// Step 2: S -> C: {t_0, ..., t_{n-1}}
	// where t_j = e(H(s_j)^y, P^xr_c)
	r := scheme.pairing.NewZr()
	ryP := scheme.pairing.NewG1()
	r.Rand()
	ryP.MulZn(scheme.yP, r)

	serverHashes := make(map[[32]byte]bool)
	var serverWG sync.WaitGroup
	var serverLock sync.RWMutex
	serverWG.Add(len(pairedSignatures))
	for _, pairedSignature := range pairedSignatures {
		go func(pairedSignature *pbc.Element) {
			// Recall that pairedSignature = H(c_i)^y.
			e_sig_rxP := scheme.pairing.NewGT()
			e_sig_rxP.PowZn(pairedSignature, r)

			hashed := sha256.Sum256(e_sig_rxP.Bytes())

			serverLock.Lock()
			serverHashes[hashed] = true
			serverLock.Unlock()

			serverWG.Done()
		}(pairedSignature)
	}
	serverWG.Wait()

	// Step 3: C computes u_i = e(H(c_i)^x, P^y)^r_c
	var intersection RawElementSlice
	var clientWG sync.WaitGroup
	var clientLock sync.RWMutex
	clientWG.Add(len(clientSignatures))
	for i, clientSignature := range clientSignatures {
		go func(signature *pbc.Element, index int) {  // every thread in go has stack of 2KB, which isn't that bad 2kb * 100k elements = 200mb of stack
			e_sig_ryP := scheme.pairing.NewGT()
			e_sig_ryP.Pair(signature, ryP)

			hashed := sha256.Sum256(e_sig_ryP.Bytes())

			_, serverHas := serverHashes[hashed]
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

type DualPSIBenchmark struct {
	clientCardinality int
	serverCardinality int

	insecureTime time.Duration
	naiveTime time.Duration

	setupTime time.Duration

	clientSigningTime time.Duration
	serverSigningTime time.Duration

	interactionTime time.Duration
	threadedTime time.Duration
	precomputeInteractionTime time.Duration
}

func BenchmarkDualPSIInteraction(isDebug bool, doGarbageCollectBetweenRuns bool, clientCardinality int, serverCardinality int) DualPSIBenchmark {
	clientSet := generateRandomSet(clientCardinality)
	serverSet := generateRandomSet(serverCardinality)

	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	insecureTime, realIntersection := findInsecureIntersection(clientSet, serverSet)
	sort.Sort(realIntersection)
	if isDebug {
		fmt.Println("Insecure intersection: ", realIntersection)
		fmt.Println("Insecure time:", insecureTime)
	}

	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	naiveTime, naiveIntersection := findNaiveHashingIntersection(clientSet, serverSet)
	sort.Sort(naiveIntersection)
	if isDebug {
		fmt.Println("Naive hashing intersection:", naiveIntersection)
		fmt.Println("Naive hashing time:", naiveTime)
	}

	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	setupTime, scheme := NewDualAPSIScheme()
	if isDebug {
		fmt.Println("Setup time:", setupTime)
	}

	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	clientSigningTime, clientSignatures :=
		scheme.generateSignaturesOnSet(clientSet, ClientParty)
	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	serverSigningTime, serverSignatures :=
		scheme.generateSignaturesOnSet(serverSet, ServerParty)
	if isDebug {
		fmt.Println("Client signing time (avg):", clientSigningTime / time.Duration(clientCardinality))
		fmt.Println("Server signing time (avg):", serverSigningTime / time.Duration(serverCardinality))
	}

	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	interactionTime, protocolIntersection := scheme.Interaction(clientSet, clientSignatures, serverSet, serverSignatures)
	sort.Sort(protocolIntersection)
	if isDebug {
		fmt.Println("Interaction time:", interactionTime)
		fmt.Println("Protocol intersection: ", protocolIntersection)
	}

	// Verify equality:
	isEqual := sameRawElementSlice(realIntersection, protocolIntersection)
	if isDebug {
		fmt.Println("Correct?", isEqual)
	}

	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	threadedTime, protocolIntersection := scheme.ThreadedInteraction(clientSet, clientSignatures, serverSet, serverSignatures)
	sort.Sort(protocolIntersection)
	if isDebug {
		fmt.Println("Threaded interaction time:", threadedTime)
		fmt.Println("Protocol threaded intersection: ", protocolIntersection)
	}

	// Verify equality:
	isEqual = sameRawElementSlice(realIntersection, protocolIntersection)
	if isDebug {
		fmt.Println("Correct?", isEqual)
	}

	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	precomputeInteractionTime, protocolIntersection := scheme.PrecomputeThreadedInteraction(clientSet, clientSignatures, serverSet, serverSignatures)
	sort.Sort(protocolIntersection)
	if isDebug {
		fmt.Println("Precompute interaction time:", precomputeInteractionTime)
		fmt.Println("Protocol threaded intersection: ", protocolIntersection)
	}

	for numThreads := 65536; numThreads < clientCardinality; numThreads = numThreads * 2 {
		if doGarbageCollectBetweenRuns {
			runtime.GC()
		}
		smartInterTime, protocolIntersection := scheme.SmarterThreadedInteraction(clientSet, clientSignatures, serverSet, serverSignatures, numThreads)
		sort.Sort(protocolIntersection)
		if isDebug {
			fmt.Println("Channel job queue interaction time with", numThreads, "threads:", smartInterTime)
			fmt.Println("Intersection:", protocolIntersection)
		}
		if doGarbageCollectBetweenRuns {
			runtime.GC()
		}
		atomicsTime, protocolIntersection := scheme.AtomicsThreadedInteraction(clientSet, clientSignatures, serverSet, serverSignatures, numThreads)
		sort.Sort(protocolIntersection)
		if isDebug {
			fmt.Println("Atomic job queue interaction time with", numThreads, "threads:", atomicsTime)
			fmt.Println("Intersection:", protocolIntersection)
		}
		if doGarbageCollectBetweenRuns {
			runtime.GC()
		}
		divisionTime, protocolIntersection := scheme.DivisionThreadedInteraction(clientSet, clientSignatures, serverSet, serverSignatures, numThreads)
		sort.Sort(protocolIntersection)
		if isDebug {
			fmt.Println("Division job queue interaction time with", numThreads, "threads:", divisionTime)
			fmt.Println("Intersection:", protocolIntersection)
		}
	}

	// Re-run with clientCardinality threads.
	numThreads := clientCardinality
	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	smartInterTime, protocolIntersection := scheme.SmarterThreadedInteraction(clientSet, clientSignatures, serverSet, serverSignatures, numThreads)
	sort.Sort(protocolIntersection)
	if isDebug {
		fmt.Println("Channel job queue interaction time with", numThreads, "threads:", smartInterTime)
		fmt.Println("Intersection:", protocolIntersection)
	}
	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	atomicsTime, protocolIntersection := scheme.AtomicsThreadedInteraction(clientSet, clientSignatures, serverSet, serverSignatures, numThreads)
	sort.Sort(protocolIntersection)
	if isDebug {
		fmt.Println("Atomic job queue interaction time with", numThreads, "threads:", atomicsTime)
		fmt.Println("Intersection:", protocolIntersection)
	}
	if doGarbageCollectBetweenRuns {
		runtime.GC()
	}
	divisionTime, protocolIntersection := scheme.DivisionThreadedInteraction(clientSet, clientSignatures, serverSet, serverSignatures, numThreads)
	sort.Sort(protocolIntersection)
	if isDebug {
		fmt.Println("Division job queue interaction time with", numThreads, "threads:", divisionTime)
		fmt.Println("Intersection:", protocolIntersection)
	}


	// Verify equality:
	isEqual = sameRawElementSlice(realIntersection, protocolIntersection)
	if isDebug {
		fmt.Println("Correct?", isEqual)
	}

	return DualPSIBenchmark{
		len(clientSignatures), len(serverSignatures),
		insecureTime, naiveTime,
		setupTime,
		clientSigningTime, serverSigningTime,
		interactionTime, threadedTime, precomputeInteractionTime,
	}
}

func findInsecureIntersection(clientSet RawElementSlice, serverSet RawElementSlice) (time.Duration, RawElementSlice) {
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

func findNaiveHashingIntersection(clientSet RawElementSlice, serverSet RawElementSlice) (time.Duration, RawElementSlice) {
	startTime := time.Now()

	// Server sends hashes to client:
	lookupTable := make(map[[32]byte]bool)
	for _, element := range serverSet {
		hashed := sha256.Sum256(element[:])
		lookupTable[hashed] = true
	}

	// Client does a naive lookup on hashes:
	var intersection RawElementSlice
	for _, element := range clientSet {
		hashed := sha256.Sum256(element[:])
		_, isInLookup := lookupTable[hashed]
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

	flag.Parse()

	if *cpuprofile != "" {
		fmt.Println("Running with profiling mode.")
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	fmt.Println("Testing Dual-APSI...")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"Size", "Insecure", "Naive", "Setup",
		"Signing (Client)", "Signing (Server)",
		"Interaction", "Interact (Thr)", "Interact (Pre)"})

	setSizes := []int{10, 100, 1000, 10000, 100000}
	for _, size := range setSizes {
		fmt.Println("Running benchmark for", size, "elements...")

		benchmark := BenchmarkDualPSIInteraction(true, true, size, size)

		table.Append([]string{
			strconv.Itoa(size),
			benchmark.insecureTime.String(),
			benchmark.naiveTime.String(),
			benchmark.setupTime.String(),
			benchmark.clientSigningTime.String(),
			benchmark.serverSigningTime.String(),
			benchmark.interactionTime.String(),
			benchmark.threadedTime.String(),
			benchmark.precomputeInteractionTime.String(),
		})
	}
	table.Render()

	fmt.Println("Testing Joux Benchmark...")
	BenchmarkJouxKeyExchange(false)

	totalRuns := 100
	fmt.Println("Running full benchmark with", totalRuns, "runs...")
	var totalSetup time.Duration
	var totalOnline time.Duration

	for i := 1; i <= totalRuns; i++ {
	    setupTime, onlineTime := BenchmarkJouxKeyExchange(false)
	    totalSetup += setupTime
	    totalOnline += onlineTime
	}

	fmt.Println("Done! Average time elapsed: ")
	fmt.Println("   (setup) ", totalSetup / time.Duration(totalRuns))
	fmt.Println("  (online) ", totalOnline / time.Duration(totalRuns))
}
