//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	kernelRuntime "github.com/CHIZI-0618/sing-ebpf/runtime"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
)

// Consumer-side aliases keep the adapter independent of the implementation
// package's concrete resource types.
type tcRuntime = kernelRuntime.TCRuntime
type tcRuntimeConfig = kernelRuntime.TCRuntimeConfig

// newTCRuntime starts and returns one complete TC resource owner backed by the
// prepared sing-ebpf TC backend.
func newTCRuntime(backend *commonEBPF.TCBackend, config tcRuntimeConfig) (tcRuntime, error) {
	config.Backend = backend
	return kernelRuntime.NewTCRuntime(config)
}

func newUnstartedTCRuntime(backend *commonEBPF.TCBackend) tcRuntime {
	return kernelRuntime.NewUnstartedTCRuntime(backend)
}

func availableLocalTCInterface(enabled bool, interfaceName string) (string, error) {
	return kernelRuntime.AvailableLocalTCInterface(enabled, interfaceName)
}