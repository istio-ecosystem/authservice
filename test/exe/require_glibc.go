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

func main() {
	currentGlibcVersion, _ := version.NewVersion("2.27")
	args := os.Args[1:]
	cmd := exec.Command("objdump", "-T", args[0])
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal("failed to check GLIBC version:", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(out.String()))
	for scanner.Scan() {
		entry := scanner.Text()
		if strings.Contains(entry, "GLIBC_") {
			line := bufio.NewScanner(strings.NewReader(entry[strings.Index(entry, "GLIBC_")+len("GLIBC_"):]))
			line.Split(bufio.ScanWords)
			for line.Scan() {
				v, _ := version.NewVersion(line.Text())
				if currentGlibcVersion.LessThan(v) {
					log.Fatal("linked to a newer GLIBC: ", line.Text())
				}
				break
			}
		}
	}
}
