//go:build with_gvisor && !no_tailscale

package outbound

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/tsnet"
)

type fakeTailscaleWatcher struct {
	notify ipn.Notify
	err    error
}

func (w *fakeTailscaleWatcher) Next() (ipn.Notify, error) {
	if w.err != nil {
		return ipn.Notify{}, w.err
	}
	return w.notify, nil
}
func (w *fakeTailscaleWatcher) Close() error { return nil }

func TestTailscaleWatcherReconnectsAfterTemporaryError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tailscale := &Tailscale{ctx: ctx, backendInitCh: make(chan struct{})}
	var watchCalls atomic.Int32
	tailscale.watchIPNBusHook = func(context.Context) (tailscaleIPNBusWatcher, error) {
		calls := watchCalls.Add(1)
		if calls == 1 {
			return &fakeTailscaleWatcher{err: errors.New("temporary EOF")}, nil
		}
		state := ipn.Running
		return &fakeTailscaleWatcher{notify: ipn.Notify{State: &state}}, nil
	}
	go tailscale.watchBackendState()
	deadline := time.After(time.Second)
	for !tailscale.backendReady.Load() {
		select {
		case <-deadline:
			t.Fatal("backend did not recover after watcher reconnect")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if watchCalls.Load() < 2 {
		t.Fatalf("watch calls = %d, want reconnect", watchCalls.Load())
	}
}

// 取消必须能中断重试等待，而不只是被循环前的 ctx 检查挡住。先前的写法在启动
// goroutine 后立刻 cancel，goroutine 常常还没进过循环就退出了 —— watchIPNBusHook
// 一次都没被调用，测试却是绿的。这里等 hook 真的被调用过再取消，确保覆盖的是
// waitTailscaleWatcherRetry 里的取消路径。
func TestTailscaleWatcherStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tailscale := &Tailscale{ctx: ctx, backendInitCh: make(chan struct{})}
	var watchCalls atomic.Int32
	subscribed := make(chan struct{}, 1)
	tailscale.watchIPNBusHook = func(context.Context) (tailscaleIPNBusWatcher, error) {
		watchCalls.Add(1)
		select {
		case subscribed <- struct{}{}:
		default:
		}
		return &fakeTailscaleWatcher{err: errors.New("temporary EOF")}, nil
	}
	done := make(chan struct{})
	go func() { tailscale.watchBackendState(); close(done) }()

	select {
	case <-subscribed:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("watcher never subscribed, cancellation path was not exercised")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not stop after cancellation")
	}
	if watchCalls.Load() < 1 {
		t.Fatal("watch hook was never invoked")
	}
	calls := watchCalls.Load()
	time.Sleep(150 * time.Millisecond)
	if watchCalls.Load() != calls {
		t.Fatalf("watch calls increased after cancellation: %d -> %d", calls, watchCalls.Load())
	}
}

func TestTailscaleStartApplyPrefsFailureClosesStartedServer(t *testing.T) {
	applyErr := errors.New("apply prefs failed")
	closeCalls := 0
	tailscale := &Tailscale{
		ctx:                 context.Background(),
		backendInitCh:       make(chan struct{}),
		startServerHook:     func() error { return nil },
		startApplyPrefsHook: func(context.Context) error { return applyErr },
		closeServerHook:     func() error { closeCalls++; return nil },
	}
	if err := tailscale.start(); !errors.Is(err, applyErr) {
		t.Fatalf("start error = %v, want wrapped apply error", err)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
	if tailscale.serverStarted.Load() {
		t.Fatal("server remained marked started after apply failure")
	}
	if err := tailscale.waitBackendInitialized(context.Background()); !errors.Is(err, applyErr) {
		t.Fatalf("initialized error = %v, want wrapped apply error", err)
	}
}

func TestTailscaleStartFailureClosesAttemptedServer(t *testing.T) {
	startErr := errors.New("start failed")
	closeCalls := 0
	tailscale := &Tailscale{
		ctx:             context.Background(),
		backendInitCh:   make(chan struct{}),
		startServerHook: func() error { return startErr },
		closeServerHook: func() error { closeCalls++; return nil },
	}
	if err := tailscale.start(); !errors.Is(err, startErr) {
		t.Fatalf("start error = %v, want start error", err)
	}
	if closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", closeCalls)
	}
}

func TestTailscaleRetryAfterCloseFailureRetiresServer(t *testing.T) {
	applyCalls := 0
	startCalls := 0
	closeCalls := 0
	applyErr := errors.New("transient apply failure")
	tailscale := &Tailscale{
		ctx:           context.Background(),
		backendInitCh: make(chan struct{}),
		startServerHook: func() error {
			startCalls++
			return nil
		},
		startApplyPrefsHook: func(context.Context) error {
			applyCalls++
			if applyCalls == 1 {
				return applyErr
			}
			return nil
		},
		closeServerHook: func() error {
			closeCalls++
			return errors.New("close failed")
		},
	}
	if err := tailscale.start(); !errors.Is(err, applyErr) {
		t.Fatalf("first start error = %v, want apply error", err)
	}
	if tailscale.serverStarted.Load() || tailscale.server != nil {
		t.Fatal("failed server was not retired after close failure")
	}
	// A close failure must not make the next attempt reuse the one-shot server.
	if err := tailscale.start(); err != nil {
		t.Fatalf("second start failed: %v", err)
	}
	if startCalls != 2 || applyCalls != 2 || closeCalls != 1 {
		t.Fatalf("attempts: start=%d apply=%d close=%d, want 2/2/1", startCalls, applyCalls, closeCalls)
	}
}

func TestTailscaleBackendInitGateKeepsAttemptError(t *testing.T) {
	tailscale := &Tailscale{backendInitGate: newTailscaleBackendInitGate()}
	oldGate := tailscale.currentBackendInitGate()
	oldErr := errors.New("old attempt")
	tailscale.completeBackendInitialized(oldGate, oldErr)
	newGate := tailscale.resetBackendInitialized()
	tailscale.completeBackendInitialized(newGate, nil)
	select {
	case <-oldGate.ch:
	default:
		t.Fatal("old gate was not completed")
	}
	if !errors.Is(oldGate.err, oldErr) {
		t.Fatalf("old gate error = %v, want %v", oldGate.err, oldErr)
	}
	if newGate.err != nil {
		t.Fatalf("new gate error = %v, want nil", newGate.err)
	}
}

func TestParseAdvertiseRoutes(t *testing.T) {
	routes, err := parseAdvertiseRoutes(TailscaleOption{AdvertiseRoutes: []string{" 10.0.0.7/24 ", "2001:db8::1/64"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0] != netip.MustParsePrefix("10.0.0.0/24") || routes[1] != netip.MustParsePrefix("2001:db8::/64") {
		t.Fatalf("unexpected routes: %v", routes)
	}

	if _, err := parseAdvertiseRoutes(TailscaleOption{AdvertiseRoutes: []string{"not-a-prefix"}}); err == nil {
		t.Fatal("invalid route accepted")
	}
}

func TestTailscaleAdvertisedRouteBoundary(t *testing.T) {
	tailscale := &Tailscale{advertisedRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
	if !tailscale.isAdvertisedRoute(netip.MustParseAddr("10.0.0.42")) {
		t.Fatal("advertised route was rejected")
	}
	if tailscale.isAdvertisedRoute(netip.MustParseAddr("10.0.1.42")) {
		t.Fatal("destination outside advertised route was accepted")
	}
}

func TestTailscaleBackendReady(t *testing.T) {
	if tailscaleBackendReady(ipn.NeedsLogin) || tailscaleBackendReady(ipn.Starting) || tailscaleBackendReady(ipn.Stopped) {
		t.Fatal("non-running backend reported ready")
	}
	if !tailscaleBackendReady(ipn.Running) {
		t.Fatal("running backend not reported ready")
	}
}

func TestTailscaleBackendStateTransitions(t *testing.T) {
	tailscale := &Tailscale{Base: NewBase(BaseOption{Name: "test"}), ctx: context.Background(), backendInitCh: make(chan struct{})}
	tailscale.observeBackendState(ipn.Running, false)
	if !tailscale.backendReady.Load() {
		t.Fatal("running backend was not marked ready")
	}
	tailscale.observeBackendState(ipn.Stopped, false)
	if tailscale.backendReady.Load() {
		t.Fatal("stopped backend remained ready")
	}
	tailscale.observeBackendState(ipn.Running, false)
	if !tailscale.backendReady.Load() {
		t.Fatal("backend did not recover to ready")
	}
}

func TestTailscaleExitNodeRetryCannotReviveStoppedBackend(t *testing.T) {
	tailscale := &Tailscale{Base: NewBase(BaseOption{Name: "test"}), ctx: context.Background(), backendInitCh: make(chan struct{})}
	applyStarted := make(chan struct{})
	allowApply := make(chan struct{})
	applyDone := make(chan struct{})
	tailscale.applyExitNodePrefsHook = func(ctx context.Context) error {
		close(applyStarted)
		defer close(applyDone)
		select {
		case <-allowApply:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	tailscale.backendIsRunningHook = func(context.Context) (bool, error) { return true, nil }
	tailscale.observeBackendState(ipn.Running, true)
	select {
	case <-applyStarted:
	case <-time.After(time.Second):
		t.Fatal("exit-node retry did not start")
	}
	tailscale.observeBackendState(ipn.Stopped, true)
	close(allowApply)
	select {
	case <-applyDone:
	case <-time.After(time.Second):
		t.Fatal("exit-node retry did not stop")
	}
	if tailscale.backendReady.Load() {
		t.Fatal("stale exit-node retry revived stopped backend")
	}
}

func TestTailscaleExitNodeRetryCannotMutateReplacedServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	oldServer := &tsnet.Server{}
	newServer := &tsnet.Server{}
	tailscale := &Tailscale{
		Base:              NewBase(BaseOption{Name: "test"}),
		ctx:               ctx,
		server:            oldServer,
		serverGeneration:  1,
		backendState:      ipn.Running,
		backendGeneration: 1,
	}
	tailscale.serverStarted.Store(true)
	applyStarted := make(chan struct{})
	allowApply := make(chan struct{})
	tailscale.applyExitNodePrefsHook = func(ctx context.Context) error {
		close(applyStarted)
		select {
		case <-allowApply:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	tailscale.backendIsRunningHook = func(context.Context) (bool, error) { return true, nil }
	tailscale.backendRetrying = true
	gate := newTailscaleBackendInitGate()
	done := make(chan struct{})
	go func() {
		tailscale.retryExitNodePrefs(ctx, 1, gate, oldServer, 1)
		close(done)
	}()
	select {
	case <-applyStarted:
	case <-time.After(time.Second):
		t.Fatal("exit-node retry did not start")
	}
	tailscale.startAccess.Lock()
	tailscale.server = newServer
	tailscale.serverGeneration = 2
	tailscale.startAccess.Unlock()
	close(allowApply)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("exit-node retry did not stop after server replacement")
	}
	if tailscale.backendReady.Load() {
		t.Fatal("stale exit-node retry marked replacement generation ready")
	}
}
