//go:build !darwin || !cgo

package hako

func startMemoryPressureMonitor() {}

func physFootprint() int64 { return -1 }

func availableMemory() int64 { return -1 }
