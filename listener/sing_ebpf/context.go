//go:build with_ebpf && (linux || android)

package sing_ebpf

import "context"

func contextBackground() context.Context {
	return context.Background()
}
