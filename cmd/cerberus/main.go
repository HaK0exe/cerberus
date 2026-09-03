// Command cerberus is the Cerberus CLI: local file/Git/web scanning,
// findings and rules inspection, remediation planning, and the
// server/mcp entrypoints for cloud deployments.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
