// Command drift is the local CLI. `drift analyze` arrives in M2.
package main

import (
	"fmt"
	"io"
	"os"
)

const version = "0.1.0"

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		_, _ = fmt.Fprintln(stdout, version)
		return 0
	}
	_, _ = fmt.Fprintln(stderr, "usage: drift version\n\ndrift analyze is not implemented yet.")
	return 2
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
