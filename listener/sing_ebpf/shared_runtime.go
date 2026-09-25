//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"github.com/CHIZI-0618/sing-ebpf/runtime"
	kernelRuntime "github.com/CHIZI-0618/sing-ebpf/runtime"
)

type sharedKernelRuntime = kernelRuntime.SharedPacketRewriteRuntime
type sharedKernelRuntimeTarget = runtime.SharedPacketRewriteRuntime

var _ = sharedKernelRuntimeTarget(nil)

func newSharedKernelRuntime(hooks sharedKernelRuntimeHooks, priority uint16) sharedKernelRuntime {
	return kernelRuntime.NewSharedPacketRewriteRuntime(kernelRuntime.SharedPacketRewriteRuntimeConfig{
		Hooks:    hooks,
		Priority: priority,
	})
}

// sharedKernelRuntimeHooks are the adapter-side callbacks sing-ebpf's shared
// packet-rewrite runtime requests.
type sharedKernelRuntimeHooks = kernelRuntime.SharedPacketRewriteHooks