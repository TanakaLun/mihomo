
// Copyright 2026 The Mihomo Authors.
//go:build android && !cgo

package main

import (
	"os"
	"os/exec"
	"strings"
	"time"
)

func init() {
	tz := os.Getenv("TZ")
	if tz == "" {
		out, err := exec.Command("/system/bin/getprop", "persist.sys.timezone").Output()
		if err != nil {
			return
		}
		tz = strings.TrimSpace(string(out))
	}

	if tz == "" {
		return
	}

	loc, err := time.LoadLocation(tz)
	if err != nil {
		return
	}

	time.Local = loc
}
