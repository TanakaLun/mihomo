//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"testing"
	"time"
)

func TestNextTCJanitorSchedule(t *testing.T) {
	cases := []struct {
		name         string
		observation  tcJanitorObservation
		wantInterval time.Duration
		wantPressure bool
	}{
		{
			name:         "empty complete table parks on idle interval",
			observation:  tcJanitorObservation{complete: true},
			wantInterval: tcJanitorIdleInterval,
			wantPressure: false,
		},
		{
			name:         "non-empty complete table keeps the regular cadence",
			observation:  tcJanitorObservation{complete: true, returnScanned: 12},
			wantInterval: tcJanitorSweepInterval,
			wantPressure: false,
		},
		{
			name:         "partial traversal keeps the regular cadence",
			observation:  tcJanitorObservation{complete: false, returnScanned: tcJanitorSweepBudget},
			wantInterval: tcJanitorSweepInterval,
			wantPressure: false,
		},
		{
			name:         "publication failure growth enters pressure",
			observation:  tcJanitorObservation{failuresGrew: true},
			wantInterval: tcJanitorPressureInterval,
			wantPressure: true,
		},
		{
			name:         "pressure persists until a full pass without failures",
			observation:  tcJanitorObservation{pressure: true, complete: false, returnScanned: 100},
			wantInterval: tcJanitorPressureInterval,
			wantPressure: true,
		},
		{
			name:         "pressure ends after a complete pass without failure growth",
			observation:  tcJanitorObservation{pressure: true, complete: true, returnScanned: 100},
			wantInterval: tcJanitorSweepInterval,
			wantPressure: false,
		},
		{
			name:         "pressure ends and an empty table parks immediately",
			observation:  tcJanitorObservation{pressure: true, complete: true},
			wantInterval: tcJanitorIdleInterval,
			wantPressure: false,
		},
		{
			name:         "pressure keeps priority over the empty-table park",
			observation:  tcJanitorObservation{pressure: true, failuresGrew: true, complete: true},
			wantInterval: tcJanitorPressureInterval,
			wantPressure: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			interval, pressure := nextTCJanitorSchedule(tc.observation)
			if interval != tc.wantInterval || pressure != tc.wantPressure {
				t.Fatalf("nextTCJanitorSchedule(%+v) = (%s, %v), want (%s, %v)",
					tc.observation, interval, pressure, tc.wantInterval, tc.wantPressure)
			}
		})
	}
}
