//go:build with_ebpf && (linux || android)

package ebpf

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cilium/ebpf/asm"
)

func TestProcessCgroupExclusive(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "cgroup.procs")
	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(path, []byte(pid+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exclusive, err := processCgroupExclusive(directory)
	if err != nil || !exclusive {
		t.Fatalf("single-process cgroup was not exclusive: exclusive=%v err=%v", exclusive, err)
	}
	if err = os.WriteFile(path, []byte(pid+"\n"+strconv.Itoa(os.Getpid()+1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exclusive, err = processCgroupExclusive(directory)
	if err != nil || exclusive {
		t.Fatalf("shared cgroup was treated as exclusive: exclusive=%v err=%v", exclusive, err)
	}
}

func TestSelfBypassInstructionsUseSocketCookie(t *testing.T) {
	for name, instructions := range map[string]asm.Instructions{
		"create":  selfBypassCreateInstructions(1),
		"release": selfBypassReleaseInstructions(1),
	} {
		found := false
		for _, instruction := range instructions {
			if instruction.IsBuiltinCall() && asm.BuiltinFunc(instruction.Constant) == asm.FnGetSocketCookie {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("%s self-bypass instructions do not read the socket cookie", name)
		}
	}
}
