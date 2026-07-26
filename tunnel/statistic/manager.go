package statistic

import (
	"os"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
		uploadTemp:         atomic.NewInt64(0),
		downloadTemp:       atomic.NewInt64(0),
		uploadBlip:         atomic.NewInt64(0),
		downloadBlip:       atomic.NewInt64(0),
		uploadTotal:        atomic.NewInt64(0),
		downloadTotal:      atomic.NewInt64(0),
		cumulativeUpload:   atomic.NewInt64(0),
		cumulativeDownload: atomic.NewInt64(0),
		pid:                int32(os.Getpid()),
	}

	go DefaultManager.handle()
}

type Manager struct {
	connections        xsync.Map[string, Tracker]
	uploadTemp         atomic.Int64
	downloadTemp       atomic.Int64
	uploadBlip         atomic.Int64
	downloadBlip       atomic.Int64
	uploadTotal        atomic.Int64
	downloadTotal      atomic.Int64
	cumulativeUpload   atomic.Int64
	cumulativeDownload atomic.Int64
	pid                int32
	memory             uint64

	saveFn    func(upload, download int64)
	saveTicker *time.Ticker
	saveDone   chan struct{}
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
	m.cumulativeUpload.Add(size)
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
	m.cumulativeDownload.Add(size)
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) CumulativeTotal() (up, down int64) {
	return m.cumulativeUpload.Load(), m.cumulativeDownload.Load()
}

func (m *Manager) SetCumulative(upload, download int64) {
	m.cumulativeUpload.Store(upload)
	m.cumulativeDownload.Store(download)
}

func (m *Manager) ResetCumulative() {
	m.cumulativeUpload.Store(0)
	m.cumulativeDownload.Store(0)
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory,
	}
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory = stat.RSS
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
}

func (m *Manager) StartAutoSave(interval time.Duration, saveFn func(upload, download int64)) {
	m.StopAutoSave()
	m.saveFn = saveFn
	m.saveTicker = time.NewTicker(interval)
	m.saveDone = make(chan struct{})
	go func() {
		for {
			select {
			case <-m.saveTicker.C:
				up := m.cumulativeUpload.Load()
				down := m.cumulativeDownload.Load()
				if m.saveFn != nil {
					m.saveFn(up, down)
				}
			case <-m.saveDone:
				return
			}
		}
	}()
}

func (m *Manager) StopAutoSave() {
	if m.saveTicker != nil {
		m.saveTicker.Stop()
		m.saveTicker = nil
	}
	if m.saveDone != nil {
		close(m.saveDone)
		m.saveDone = nil
	}
	m.saveFn = nil
}

func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)

	for range ticker.C {
		m.uploadBlip.Store(m.uploadTemp.Swap(0))
		m.downloadBlip.Store(m.downloadTemp.Swap(0))
	}
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}
