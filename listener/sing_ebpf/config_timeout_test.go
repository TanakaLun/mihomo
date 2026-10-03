//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"testing"
	"time"
)

func TestNormalizeUDPTimeout(t *testing.T) {
	tests := []struct {
		name    string
		seconds int64
		want    time.Duration
		wantErr bool
	}{
		{name: "omitted or zero", seconds: 0, want: 5 * time.Minute},
		{name: "one second", seconds: 1, wantErr: true},
		{name: "four seconds", seconds: 4, wantErr: true},
		{name: "short timeout", seconds: 30, want: 30 * time.Second},
		{name: "explicit default", seconds: 300, want: 5 * time.Minute},
		{name: "custom timeout", seconds: 600, want: 10 * time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeUDPTimeout(tt.seconds)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeUDPTimeout(%d) expected error", tt.seconds)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeUDPTimeout(%d) unexpected error: %v", tt.seconds, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeUDPTimeout(%d) = %s, want %s", tt.seconds, got, tt.want)
			}
		})
	}
}
