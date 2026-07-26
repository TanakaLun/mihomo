package profile

import (
	"github.com/metacubex/mihomo/common/atomic"
)

// StoreSelected is a global switch for storing selected proxy to cache
var StoreSelected = atomic.NewBool(true)

// StoreTrafficCumulative is a global switch for storing cumulative traffic
var StoreTrafficCumulative = atomic.NewBool(false)
