package hako

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
)

const (
	goCrashReportFileName         = "go-crash.log"
	goCrashReportPreviousFileName = "go-crash.previous.log"

	goCrashReportMaxBytes = 128 << 10

	goCrashReportTruncationNotice = "\n[hako: traceback truncated]\n"
)

var goCrashReportMu sync.Mutex

func armGoCrashOutputAt(basePath string) error {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()

	if basePath == "" {
		return errors.New("hako: Go crash output needs a base path")
	}
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return fmt.Errorf("hako: create Go crash output directory: %w", err)
	}

	live := filepath.Join(basePath, goCrashReportFileName)
	previous := filepath.Join(basePath, goCrashReportPreviousFileName)

	if info, err := os.Stat(live); err == nil && info.Size() > 0 {
		if err := os.Rename(live, previous); err != nil {
			return fmt.Errorf("hako: archive previous Go crash output: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("hako: stat Go crash output: %w", err)
	} else if err == nil {
		_ = os.Remove(live)
	}

	file, err := os.OpenFile(live, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("hako: open Go crash output: %w", err)
	}
	defer file.Close()

	if err := debug.SetCrashOutput(file, debug.CrashOptions{}); err != nil {
		return fmt.Errorf("hako: set Go crash output: %w", err)
	}
	return nil
}

func disarmGoCrashOutput() error {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()
	return debug.SetCrashOutput(nil, debug.CrashOptions{})
}

func consumeGoCrashReportAt(basePath string) (string, error) {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()

	if basePath == "" {
		return "", errors.New("hako: Go crash report needs a base path")
	}
	path := filepath.Join(basePath, goCrashReportPreviousFileName)

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	info, statErr := file.Stat()
	if statErr == nil && !info.Mode().IsRegular() {
		_ = file.Close()
		_ = os.Remove(path)
		return "", errors.New("hako: Go crash report is not a regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, goCrashReportMaxBytes+1))
	_ = file.Close()

	if removeErr := os.Remove(path); removeErr != nil && readErr == nil {
		return "", fmt.Errorf("hako: remove Go crash report: %w", removeErr)
	}
	if readErr != nil {
		return "", fmt.Errorf("hako: read Go crash report: %w", readErr)
	}

	if len(data) > goCrashReportMaxBytes {
		return string(data[:goCrashReportMaxBytes]) + goCrashReportTruncationNotice, nil
	}
	return string(data), nil
}

func ConsumeGoCrashReport() (*StringBox, error) {
	basePath, err := goCrashReportBasePath()
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	report, err := consumeGoCrashReportAt(basePath)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(report), nil
}

func goCrashReportBasePath() (string, error) {
	setupMu.Lock()
	defer setupMu.Unlock()
	if !setupDone || setupGoCrashReportBasePath == "" {
		return "", errors.New("hako: Go crash report before Setup")
	}
	return setupGoCrashReportBasePath, nil
}
