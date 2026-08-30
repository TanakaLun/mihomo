//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const packetWarningInterval = 10 * time.Second

type warningLogger = func(format string, args ...any)

type warningLimiter struct {
	access     sync.Mutex
	next       time.Time
	suppressed uint64
}

func (l *warningLimiter) allow(now time.Time) (bool, uint64) {
	l.access.Lock()
	defer l.access.Unlock()
	if now.Before(l.next) {
		l.suppressed++
		return false, 0
	}
	suppressed := l.suppressed
	l.suppressed = 0
	l.next = now.Add(packetWarningInterval)
	return true, suppressed
}

func (l *warningLimiter) warn(logger warningLogger, message ...any) {
	allowed, suppressed := l.allow(time.Now())
	if !allowed {
		return
	}
	text := make([]string, 0, len(message))
	for _, part := range message {
		text = append(text, fmt.Sprint(part))
	}
	if suppressed > 0 {
		text = append(text, fmt.Sprintf("(%d similar messages suppressed)", suppressed))
	}
	logger("%s", strings.Join(text, " "))
}

type udpWarningLimiters struct {
	accept              warningLimiter
	packetInfo          warningLimiter
	originalDestination warningLimiter
	cleanup             warningLimiter
}
