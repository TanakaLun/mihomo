//go:build windows

package sing_tun

import (
	"net/netip"

	"github.com/metacubex/mihomo/component/route"
	"github.com/metacubex/mihomo/log"
)

// applyBypassRoutesLocked reconciles the kernel-level bypass routes on the
// physical data path so traffic to the given prefixes never enters the TUN
// device. It must be called with l.bypassMutex held.
func (l *Listener) applyBypassRoutesLocked(prefixes []netip.Prefix) {
	if err := l.ensureBypassRouter(); err != nil {
		log.Warnln("[TUN] bypass-rule-set: windows route router unavailable: %s", err.Error())
		return
	}
	installed, skipped, err := l.bypassRouter.Apply(prefixes)
	if err != nil {
		if installed == 0 {
			log.Warnln("[TUN] bypass-rule-set: apply bypass routes: %s", err.Error())
		} else {
			log.Infoln("[TUN] bypass-rule-set: installed %d physical bypass routes (partial: %s; skipped=%d)", installed, err.Error(), skipped)
		}
		return
	}
	if installed == 0 && skipped == 0 {
		log.Debugln("[TUN] bypass-rule-set: no route change")
		return
	}
	if skipped > 0 {
		log.Infoln("[TUN] bypass-rule-set: installed %d physical bypass routes, skipped %d (protected by TUN addressing or no physical covering route)", installed, skipped)
	} else {
		log.Debugln("[TUN] bypass-rule-set: installed %d physical bypass routes", installed)
	}
}

// ensureBypassRouter lazily creates the Windows route reconciler. The TUN
// interface must exist for ConvertInterfaceAliasToLuid to resolve its LUID,
// so creation is deferred until the first Apply.
func (l *Listener) ensureBypassRouter() error {
	if l.bypassRouter != nil {
		return nil
	}
	router, err := route.NewRouter(l.tunName, protectedBypassPrefixes(l))
	if err != nil {
		return err
	}
	l.bypassRouter = router
	return nil
}

// protectedBypassPrefixes returns the prefixes that must never be bypassed:
// the TUN device's own addressing and the loopback ranges. Traffic to these
// always stays on the TUN/interception path.
func protectedBypassPrefixes(l *Listener) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(l.options.Inet4Address)+len(l.options.Inet6Address)+len(l.options.LoopbackAddress))
	prefixes = append(prefixes, l.options.Inet4Address...)
	prefixes = append(prefixes, l.options.Inet6Address...)
	for _, addr := range l.options.LoopbackAddress {
		if bits := addr.BitLen(); bits > 0 {
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits))
		}
	}
	for i := range prefixes {
		prefixes[i] = prefixes[i].Masked()
	}
	return prefixes
}

// resetBypassRoutes removes every bypass route installed by this listener.
func (l *Listener) resetBypassRoutes() {
	l.bypassMutex.Lock()
	defer l.bypassMutex.Unlock()
	if l.bypassRouter == nil {
		return
	}
	if err := l.bypassRouter.Reset(); err != nil {
		log.Warnln("[TUN] bypass-rule-set: reset bypass routes: %s", err.Error())
	}
}
