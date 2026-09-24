package statistic

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/TokenPLS/Hako/common/atomic"
)


func waitUntil(t *testing.T, deadline time.Duration, condition func() bool) bool {
	t.Helper()
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		if condition() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return condition()
}

func TestResumingDoesNotPublishTheIdleAccumulation(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	const idleBytes = 500 << 20
	manager.PushUploaded("direct", idleBytes)
	manager.PushDownloaded("direct", idleBytes)
	time.Sleep(1500 * time.Millisecond)

	if up, down := manager.uploadBlip.Load(), manager.downloadBlip.Load(); up != 0 || down != 0 {
		t.Fatalf("the idle sampler published a rate (up=%d down=%d); it should not have been "+
			"sampling at all", up, down)
	}

	manager.Now()

	if !waitUntil(t, 3*time.Second, func() bool {
		return manager.uploadTemp.Load() == 0
	}) {
		t.Fatalf("the sampler did not clear the idle accumulation: uploadTemp=%d", manager.uploadTemp.Load())
	}

	time.Sleep(2500 * time.Millisecond)
	if up := manager.uploadBlip.Load(); up >= idleBytes {
		t.Fatalf("published %d bytes/s after resuming; the whole idle span was reported as one "+
			"second of traffic, which is the fake spike this design exists to avoid", up)
	}
	if down := manager.downloadBlip.Load(); down >= idleBytes {
		t.Fatalf("published %d bytes/s down after resuming, same fake spike", down)
	}
}

func TestSamplerPublishesRealTrafficWhileBeingRead(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	manager.Now()

	const perSecond = 3 << 20
	published := waitUntil(t, 6*time.Second, func() bool {
		manager.PushUploaded("direct", perSecond/4)
		manager.Now()
		time.Sleep(120 * time.Millisecond)
		return manager.uploadBlip.Load() > 0
	})
	if !published {
		t.Fatal("a sampler being read every 120 ms never published a rate, so reads are not " +
			"keeping it alive and the rate view would sit at zero")
	}
}

func TestSamplerStopsWhenNobodyReads(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	manager.Now()
	manager.PushUploaded("direct", 4<<20)

	if !waitUntil(t, 4*time.Second, func() bool { return manager.uploadBlip.Load() > 0 }) {
		t.Fatal("never published a rate while being read")
	}

	time.Sleep(sampleIdleTimeout + time.Second)
	manager.uploadTemp.Store(0)
	manager.PushUploaded("direct", 7<<20)
	time.Sleep(2 * time.Second)

	if manager.uploadTemp.Load() != 7<<20 {
		t.Fatalf("uploadTemp = %d after the idle timeout, want the pushed 7 MiB left untouched; "+
			"the sampler is still running with no reader", manager.uploadTemp.Load())
	}
}

func TestSnapshotDoesNotWakeTheSampler(t *testing.T) {
	manager := newTestManager()
	go manager.handle()

	manager.Snapshot()
	manager.PushUploaded("direct", 9<<20)
	time.Sleep(2 * time.Second)

	if got := manager.uploadBlip.Load(); got != 0 {
		t.Fatalf("Snapshot woke the sampler: published %d bytes/s", got)
	}
	if manager.lastReadAt.Load() != 0 {
		t.Fatal("Snapshot recorded a rate read")
	}
}

func newTestManager() *Manager {
	return &Manager{
		uploadTemp:         atomic.NewInt64(0),
		downloadTemp:       atomic.NewInt64(0),
		uploadBlip:         atomic.NewInt64(0),
		downloadBlip:       atomic.NewInt64(0),
		uploadTotal:        atomic.NewInt64(0),
		downloadTotal:      atomic.NewInt64(0),
		proxyUploadTemp:    atomic.NewInt64(0),
		proxyDownloadTemp:  atomic.NewInt64(0),
		proxyUploadBlip:    atomic.NewInt64(0),
		proxyDownloadBlip:  atomic.NewInt64(0),
		proxyUploadTotal:   atomic.NewInt64(0),
		proxyDownloadTotal: atomic.NewInt64(0),
		lastReadAt:         atomic.NewInt64(0),
		sampleWake:         make(chan struct{}, 1),
	}
}

func TestMemorySamplingAndCachedSnapshotsAreConcurrent(t *testing.T) {
	manager := newTestManager()
	manager.pid = int32(os.Getpid())
	if manager.Memory() == 0 {
		t.Skip("host RSS sampling unavailable")
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(sample bool) {
			defer workers.Done()
			<-start
			for n := 0; n < 500; n++ {
				if sample {
					manager.Memory()
				} else {
					manager.Snapshot()
				}
			}
		}(worker%2 == 0)
	}
	close(start)
	workers.Wait()
}

func TestMemorySampleIsVisibleInCachedSnapshot(t *testing.T) {
	manager := newTestManager()
	manager.pid = int32(os.Getpid())
	if got := manager.Snapshot().Memory; got != 0 {
		t.Fatalf("unsampled snapshot = %d", got)
	}
	sampled := manager.Memory()
	if sampled == 0 {
		t.Skip("host RSS sampling unavailable")
	}
	if got := manager.Snapshot().Memory; got != sampled {
		t.Fatalf("snapshot=%d, last sample=%d", got, sampled)
	}
}
