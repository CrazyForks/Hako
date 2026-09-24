//go:build !darwin || !cgo

package hako

func processCPUTimeNanoseconds() int64 { return -1 }
