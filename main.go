package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lcuopc -lcudart
#include "wrapper.h"
#include <stdlib.h>
*/
import "C"

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"
	"unsafe"
)

const (
	threadsPerBlock = 256
	blocksPerLaunch = 1 << 18
)

func main() {
	first8 := flag.String("first", "", "first 8 hex chars (required)")
	last8  := flag.String("last", "", "last 8 hex chars (required)")
	targetBits := flag.Int("bits", 33, "leading zero bits required")
	maxLaunches := flag.Int("max", 200, "max kernel launches (each ~67M hashes)")
	runTest := flag.Bool("test", false, "run GPU SHA-512 correctness test and exit")
	randOffset := flag.Bool("rand", false, "use random nonce offset")
	flag.Parse()

	if *runTest {
		runGPUSelfTest()
		return
	}

	if *first8 == "" || *last8 == "" {
		fmt.Fprintf(os.Stderr, "Usage: cuopc -first=<8hex> -last=<8hex> [-bits=33] [-max=200] [-rand]\n")
		fmt.Fprintf(os.Stderr, "       cuopc -test\n")
		os.Exit(1)
	}
	if len(*first8) != 8 || len(*last8) != 8 {
		fmt.Fprintf(os.Stderr, "first and last must each be exactly 8 hex chars\n")
		os.Exit(1)
	}

	nonceOffset := uint64(0)
	if *randOffset {
		var buf [8]byte
		rand.Read(buf[:])
		nonceOffset = binary.LittleEndian.Uint64(buf[:])
		nonceOffset &= (1 << 58) - 1
		fmt.Printf("  Nonce offset: 0x%016x\n", nonceOffset)
	}

	hashesPerLaunch := uint64(blocksPerLaunch) * uint64(threadsPerBlock)
	fmt.Println("=== UUID v4 SHA-512 Cracker (CUDA) ===")
	fmt.Printf("  Fixed first: %s\n", *first8)
	fmt.Printf("  Fixed last:  %s\n", *last8)
	fmt.Printf("  Target:      %d leading zero bits (raw 16 bytes)\n", *targetBits)
	fmt.Printf("  Per launch:  %d hashes\n", hashesPerLaunch)
	fmt.Println()

	cfirst := C.CString(*first8)
	clast  := C.CString(*last8)
	defer C.free(unsafe.Pointer(cfirst))
	defer C.free(unsafe.Pointer(clast))

	if C.init_cracker(cfirst, clast) != 0 {
		fmt.Fprintln(os.Stderr, "init_cracker failed")
		os.Exit(1)
	}
	defer C.cleanup_cracker()

	startTime := time.Now()
	totalHashes := uint64(0)

	for launch := 0; launch < *maxLaunches; launch++ {
		baseNonce := nonceOffset + uint64(launch)*hashesPerLaunch

		if C.launch_kernel(C.uint64_t(baseNonce), C.uint32_t(blocksPerLaunch), C.uint32_t(threadsPerBlock)) != 0 {
			fmt.Fprintln(os.Stderr, "kernel launch failed")
			os.Exit(1)
		}

		var resultNonce C.uint64_t
		pollRet := C.poll_result(&resultNonce)

		if pollRet == 1 {
			nonce := uint64(resultNonce)
			elapsed := time.Since(startTime)
			attempts := nonce - baseNonce + totalHashes

			raw := nonceToRaw(nonce, *first8, *last8)
			uuid := rawToUUID(raw)
			fmt.Printf("\n========== FOUND ==========\n")
			fmt.Printf("  Nonce:   %d (0x%x)\n", nonce, nonce)
			fmt.Printf("  UUID:    %s\n", uuid)
			fmt.Printf("  Raw hex: %s\n", hex.EncodeToString(raw))
			verified := verifyRaw(raw, *targetBits)
			if verified {
				fmt.Printf("  SHA-512 verified OK\n")
			} else {
				fmt.Printf("  verification FAILED\n")
			}
			fmt.Printf("  Time:    %v\n", elapsed.Round(time.Millisecond))
			fmt.Printf("  Hashes:  ~%d (%.2e)\n", attempts, float64(attempts))
			fmt.Printf("  Speed:   %.2f MH/s\n", float64(attempts)/elapsed.Seconds()/1e6)
			return
		}

		totalHashes += hashesPerLaunch
		elapsed := time.Since(startTime).Seconds()
		fmt.Printf("  launch %3d done | %d hashes | %.1f MH/s\n",
			launch+1, totalHashes, float64(totalHashes)/elapsed/1e6)
	}

	fmt.Printf("\nNo result after %d launches (%.2e hashes).\n", *maxLaunches, float64(totalHashes))
}

func runGPUSelfTest() {
	// Test with known raw 16 bytes: eb3668950e7c4cd7991011d87ea440bd
	// SHA-512 of these raw bytes should start with 000000000e...
	rawHex := "eb3668950e7c4cd7991011d87ea440bd"
	raw, _ := hex.DecodeString(rawHex)

	fmt.Printf("GPU SHA-512 self-test (16 raw bytes)\n")
	fmt.Printf("  Input:  %s\n", rawHex)

	cpuHash := sha512.Sum512(raw)
	cpuH0 := binary.BigEndian.Uint64(cpuHash[:8])
	fmt.Printf("  CPU H0: 0x%016x\n", cpuH0)

	ct := C.CString(string(raw))
	gpuH0 := uint64(C.test_sha512_gpu(ct))
	C.free(unsafe.Pointer(ct))
	fmt.Printf("  GPU H0: 0x%016x\n", gpuH0)

	if cpuH0 == gpuH0 {
		fmt.Println("  PASS")
	} else {
		fmt.Println("  FAIL: H0 mismatch")
		os.Exit(1)
	}
}

// nonceToRaw builds the raw 16-byte UUID from nonce, matching kernel logic
func nonceToRaw(nonce uint64, first8, last8 string) []byte {
	raw := make([]byte, 16)

	fb, _ := hex.DecodeString(first8)
	lb, _ := hex.DecodeString(last8)
	copy(raw[0:4], fb)

	raw[4] = byte((nonce >> 8) & 0xFF)
	raw[5] = byte(nonce & 0xFF)
	raw[6] = 0x40 | byte((nonce>>16)&0x0F)
	raw[7] = byte((nonce >> 20) & 0xFF)
	raw[8] = 0x80 | byte((nonce>>28)&0x3F)
	raw[9] = byte((nonce >> 34) & 0xFF)
	raw[10] = byte((nonce >> 42) & 0xFF)
	raw[11] = byte((nonce >> 50) & 0xFF)

	copy(raw[12:16], lb)
	return raw
}

// rawToUUID converts 16 raw bytes to UUID string format
func rawToUUID(raw []byte) string {
	h := hex.EncodeToString(raw)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func verifyRaw(raw []byte, targetBits int) bool {
	hash := sha512.Sum512(raw)

	leadingZeros := 0
	for _, b := range hash[:] {
		if b == 0 {
			leadingZeros += 8
		} else {
			for bit := 7; bit >= 0; bit-- {
				if b&(1<<uint(bit)) != 0 {
					goto done
				}
				leadingZeros++
			}
			break
		}
	}
done:
	fmt.Printf("  SHA-512: %x...\n", hash[:8])
	fmt.Printf("  Leading zero bits: %d (need %d)\n", leadingZeros, targetBits)
	return leadingZeros >= targetBits
}
