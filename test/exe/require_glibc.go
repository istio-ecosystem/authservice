// This script checks (via objdump) whether the ELF file is linked to a newer GLIBC version than the
// one required by the runtime environment constraint (currently it is 2.27).
//
// To use: go run test/exe/require_glibc.go <path-to-an-elf-binary>
package main

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"os/exec"
	"strings"

	version "github.com/hashicorp/go-version"
)

const glibCPrefix = "GLIBC_"
const requiredGlibCVersion = "2.27" // This is chosen arbitrarily, but older than the one in ubi8.

var glibCPrefixLength = len(glibCPrefix)
var requiredGlibC, _ = version.NewVersion(requiredGlibCVersion)

func main() {
	args := os.Args[1:]
	if len(args) < 1 {
		log.Fatal("Usage: go run test/exe/require_glibc.go <path-to-an-elf-binary>")
	}

	// Check for dynamic symbols: Reference: https://man7.org/linux/man-pages/man1/objdump.1.html.
	cmd := exec.Command("objdump", "-T", args[0])
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal("Failed to check GLIBC version:", err)
	}
	// The following scans the objdump output for the GLIBC version.
	//
	// The objdump output is in the form similar to:
	// 0000000000000000      DF *UND*  0000000000000000  GLIBC_2.2.5 __libc_start_main
	// 0000000000000000  w   DF *UND*  0000000000000000  GLIBC_2.2.5 __cxa_finalize
	// 0000000000000000      DF *UND*  0000000000000000  GLIBC_2.2.5 ceilf
	// 0000000000000000      DF *UND*  0000000000000000  GLIBC_2.2.5 frexp
	// ...
	scanner := bufio.NewScanner(strings.NewReader(out.String()))
	for scanner.Scan() {
		entry := scanner.Text()
		if strings.Contains(entry, glibCPrefix) {
			line := bufio.NewScanner(strings.NewReader(entry[strings.Index(entry, glibCPrefix)+glibCPrefixLength:]))
			line.Split(bufio.ScanWords)
			// Here we have something like: "2.2.5 __libc_start_main" or "GLIBC_2.3   __ctype_b_loc".
			for line.Scan() {
				v, err := version.NewVersion(line.Text())
				if err != nil {
					// This is improbable, but when it is failed, we surely want to fail the test, since
					// by then the objdump has bugs.
					log.Fatal("Failed to parse GLIBC version:", err)
				}
				// We require the linked GLIBC is NOT newer than the one required by the runtime environment.
				if requiredGlibC.LessThan(v) {
					log.Fatal("Linked to a newer GLIBC: ", line.Text())
				}
				break
			}
		}
	}
}
