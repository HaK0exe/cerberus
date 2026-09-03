// Command cerberus-worker is the queue-consuming scan worker
// entrypoint (ECS/Fargate or Lambda). Sprint 4. Not yet implemented.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "cerberus-worker: not implemented yet (see Sprint 4)")
	os.Exit(1)
}
