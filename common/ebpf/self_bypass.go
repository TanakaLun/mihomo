//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

const selfBypassSocketCapacity = 65536

// SelfBypass owns the socket-cookie map used by the local TC classifier. The
// map is populated by cgroup hooks when the process has an exclusive cgroup,
// or by the socket control callback when cgroup attachment is unavailable.
type SelfBypass struct {
	access   sync.RWMutex
	sockets  *CiliumEBPF.Map
	programs [2]*CiliumEBPF.Program
	links    [2]link.Link
	cgroup   atomic.Bool
}

func NewSelfBypass() (*SelfBypass, error) {
	_ = raiseMemlockLimit()
	sockets, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       "sb_self_sockets",
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: selfBypassSocketCapacity,
	})
	if err != nil {
		return nil, E.Cause(err, "create eBPF self-bypass socket map")
	}
	return &SelfBypass{sockets: sockets}, nil
}

// Map returns the map that must be shared with the local TC programs.
func (b *SelfBypass) Map() *CiliumEBPF.Map {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.sockets
}

// AttachCgroup enables automatic socket-cookie registration when the current
// cgroup is exclusive to this process. A failure leaves the map usable by the
// userspace registration fallback.
func (b *SelfBypass) AttachCgroup() error {
	if b == nil {
		return E.New("eBPF self-bypass map is unavailable")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.sockets == nil {
		return E.New("eBPF self-bypass map is unavailable")
	}
	if b.links[0] != nil || b.links[1] != nil {
		return nil
	}
	cgroupPath, err := DetectProcessCgroup2Path()
	if err != nil {
		return E.Cause(err, "detect process cgroup v2")
	}
	exclusive, err := processCgroupExclusive(cgroupPath)
	if err != nil {
		return err
	}
	if !exclusive {
		return E.New("process cgroup contains other processes")
	}
	createProgram, err := newSelfBypassCreateProgram(b.sockets.FD())
	if err != nil {
		return err
	}
	releaseProgram, err := newSelfBypassReleaseProgram(b.sockets.FD())
	if err != nil {
		_ = createProgram.Close()
		return err
	}
	createLink, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroupPath, Attach: CiliumEBPF.AttachCGroupInetSockCreate, Program: createProgram,
	})
	if err != nil {
		_ = releaseProgram.Close()
		_ = createProgram.Close()
		return E.Cause(err, "attach eBPF self-bypass socket-create hook")
	}
	releaseLink, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroupPath, Attach: CiliumEBPF.AttachCgroupInetSockRelease, Program: releaseProgram,
	})
	if err != nil {
		_ = createLink.Close()
		_ = releaseProgram.Close()
		_ = createProgram.Close()
		return E.Cause(err, "attach eBPF self-bypass socket-release hook")
	}
	b.programs = [2]*CiliumEBPF.Program{createProgram, releaseProgram}
	b.links = [2]link.Link{createLink, releaseLink}
	b.cgroup.Store(true)
	return nil
}

func (b *SelfBypass) CgroupAttached() bool {
	return b != nil && b.cgroup.Load()
}

func newSelfBypassCreateProgram(mapFD int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         "sb_self_create",
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCGroupInetSockCreate,
		License:      "GPL",
		Instructions: selfBypassCreateInstructions(mapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass socket-create hook")
	}
	return program, nil
}

func newSelfBypassReleaseProgram(mapFD int) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         "sb_self_release",
		Type:         CiliumEBPF.CGroupSock,
		AttachType:   CiliumEBPF.AttachCgroupInetSockRelease,
		License:      "GPL",
		Instructions: selfBypassReleaseInstructions(mapFD),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF self-bypass socket-release hook")
	}
	return program, nil
}

func selfBypassCreateInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.StoreImm(asm.RFP, -12, 1, asm.Word),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -12),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
}

func selfBypassReleaseInstructions(mapFD int) asm.Instructions {
	return asm.Instructions{
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
}

// RegisterSocket records a socket created by sing-box when cgroup hooks cannot
// be attached. It performs one SO_COOKIE read and one map update per socket.
func (b *SelfBypass) RegisterSocket(rawConn syscall.RawConn) error {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.sockets == nil || b.cgroup.Load() {
		return nil
	}
	var cookie uint64
	err := control.Raw(rawConn, func(fd uintptr) error {
		var err error
		cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		return err
	})
	if err != nil {
		return E.Cause(err, "read socket cookie for eBPF self-bypass")
	}
	if cookie == 0 {
		return E.New("socket returned an empty eBPF self-bypass cookie")
	}
	value := uint32(1)
	if err = b.sockets.Update(&cookie, &value, CiliumEBPF.UpdateAny); err != nil {
		return E.Cause(err, "register eBPF self-bypass socket")
	}
	return nil
}

func processCgroupExclusive(path string) (bool, error) {
	file, err := os.Open(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, E.Cause(err, "read process cgroup members")
	}
	defer file.Close()
	pid := os.Getpid()
	found := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		member, parseErr := strconv.Atoi(line)
		if parseErr != nil {
			return false, E.Cause(parseErr, "parse process cgroup member")
		}
		if member != pid {
			return false, nil
		}
		found = true
	}
	if err = scanner.Err(); err != nil {
		return false, E.Cause(err, "read process cgroup members")
	}
	return found, nil
}

func (b *SelfBypass) closeHooks() error {
	if b == nil {
		return nil
	}
	var closeErr error
	for index := len(b.links) - 1; index >= 0; index-- {
		if b.links[index] != nil {
			closeErr = E.Errors(closeErr, b.links[index].Close())
			b.links[index] = nil
		}
	}
	for index := len(b.programs) - 1; index >= 0; index-- {
		if b.programs[index] != nil {
			closeErr = E.Errors(closeErr, b.programs[index].Close())
			b.programs[index] = nil
		}
	}
	b.cgroup.Store(false)
	return closeErr
}

func (b *SelfBypass) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	closeErr := b.closeHooks()
	if b.sockets != nil {
		closeErr = E.Errors(closeErr, b.sockets.Close())
		b.sockets = nil
	}
	return closeErr
}
