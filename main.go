package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lcuopc -lcudart
#include "wrapper.h"
#include <stdlib.h>
*/
import "C"

import (
	"crypto/sha512"
	"encoding/binary"
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
	flag.Parse()

	if *runTest {
		runGPUSelfTest()
		return
	}

	if *first8 == "" || *last8 == "" {
		fmt.Fprintf(os.Stderr, "Usage: cuopc -first=<8hex> -last=<8hex> [-bits=33] [-max=200]\n")
		fmt.Fprintf(os.Stderr, "       cuopc -test\n")
		os.Exit(1)
	}
	if len(*first8) != 8 || len(*last8) != 8 {
		fmt.Fprintf(os.Stderr, "first and last must each be exactly 8 hex chars\n")
		os.Exit(1)
	}

	hashesPerLaunch := uint64(blocksPerLaunch) * uint64(threadsPerBlock)
	fmt.Println("=== UUID v4 SHA-512 Cracker (CUDA) ===")
	fmt.Printf("  Fixed first: %s\n", *first8)
	fmt.Printf("  Fixed last:  %s\n", *last8)
	fmt.Printf("  Target:      %d leading zero bits\n", *targetBits)
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
		baseNonce := uint64(launch) * hashesPerLaunch

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

			uuid := buildUUID(nonce, *first8, *last8)
			fmt.Printf("\n========== FOUND ==========\n")
			fmt.Printf("  Nonce:   %d (0x%x)\n", nonce, nonce)
			fmt.Printf("  UUID:    %s\n", uuid)
			verified := verify(uuid, *targetBits)
			if verified {
				fmt.Printf("  SHA-512 verified OK\n")
			} else {
				fmt.Printf("  verification FAILED (kernel bug)\n")
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
	testUUID := "deadbeef-cafe-4bad-8ead-0123456789ab"
	fmt.Printf("GPU SHA-512 self-test\n")
	fmt.Printf("  Input:  %s\n", testUUID)

	cpuHash := sha512.Sum512([]byte(testUUID))
	cpuH0 := binary.BigEndian.Uint64(cpuHash[:8])
	fmt.Printf("  CPU H0: 0x%016x\n", cpuH0)

	ct := C.CString(testUUID)
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

func buildUUID(nonce uint64, first8, last8 string) string {
	u := make([]byte, 36)

	u[0] = first8[0]; u[1] = first8[1]; u[2] = first8[2]; u[3] = first8[3]
	u[4] = first8[4]; u[5] = first8[5]; u[6] = first8[6]; u[7] = first8[7]
	u[8] = '-'

	u[9]  = hexNibble((nonce >> 0) & 0xF)
	u[10] = hexNibble((nonce >> 4) & 0xF)
	u[11] = hexNibble((nonce >> 8) & 0xF)
	u[12] = hexNibble((nonce >> 12) & 0xF)
	u[13] = '-'

	u[14] = '4'
	u[15] = hexNibble((nonce >> 16) & 0xF)
	u[16] = hexNibble((nonce >> 20) & 0xF)
	u[17] = hexNibble((nonce >> 24) & 0xF)
	u[18] = '-'

	yChars := []byte{'8', '9', 'a', 'b'}
	u[19] = yChars[(nonce>>28)&0x3]
	u[20] = hexNibble((nonce >> 30) & 0xF)
	u[21] = hexNibble((nonce >> 34) & 0xF)
	u[22] = hexNibble((nonce >> 38) & 0xF)
	u[23] = '-'

	u[24] = hexNibble((nonce >> 42) & 0xF)
	u[25] = hexNibble((nonce >> 46) & 0xF)
	u[26] = hexNibble((nonce >> 50) & 0xF)
	u[27] = hexNibble((nonce >> 54) & 0xF)
	u[28] = last8[0]; u[29] = last8[1]; u[30] = last8[2]; u[31] = last8[3]
	u[32] = last8[4]; u[33] = last8[5]; u[34] = last8[6]; u[35] = last8[7]

	return string(u)
}

func hexNibble(n uint64) byte {
	if n < 10 {
		return byte('0' + n)
	}
	return byte('a' + n - 10)
}

func verify(uuid string, targetBits int) bool {
	hash := sha512.Sum512([]byte(uuid))

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
