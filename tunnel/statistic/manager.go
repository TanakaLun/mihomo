package statistic

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
	"github.com/metacubex/mihomo/component/profile"
	C "github.com/metacubex/mihomo/constant"
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
		destRecords:        make(map[string]*DestinationRecord),
	}

	go DefaultManager.handle()
}

// DestinationRecord stores the aggregated traffic of one destination & process.
type DestinationRecord struct {
	Host          string    `json:"host"`
	Process       string    `json:"process"`
	VisitCount    int64     `json:"visitCount"`
	UploadTotal   int64     `json:"uploadTotal"`
	DownloadTotal int64     `json:"downloadTotal"`
	LastSeen      time.Time `json:"lastSeen"`
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

	destMu      sync.Mutex
	destRecords map[string]*DestinationRecord

	saveFn     func()
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
	if profile.StoreTrafficCumulative.Load() {
		m.cumulativeUpload.Add(size)
	}
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
	if profile.StoreTrafficCumulative.Load() {
		m.cumulativeDownload.Add(size)
	}
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

// RecordDestination aggregates the final upload/download of one handled
// connection into its (host/IP, process) entry. Called on connection close.
func (m *Manager) RecordDestination(metadata *C.Metadata, upload, download int64) {
	if !profile.StoreTrafficDestination.Load() {
		return
	}

	host := metadata.RuleHost()
	if host == "" {
		if !metadata.DstIP.IsValid() {
			return
		}
		host = metadata.DstIP.String()
	}
	key := host + "\x00" + metadata.Process

	m.destMu.Lock()
	record, ok := m.destRecords[key]
	if !ok {
		record = &DestinationRecord{
			Host:    host,
			Process: metadata.Process,
		}
		m.destRecords[key] = record
	}
	record.VisitCount++
	record.UploadTotal += upload
	record.DownloadTotal += download
	record.LastSeen = time.Now()
	m.destMu.Unlock()
}

// DestinationRecords returns a snapshot of the destination aggregation table.
func (m *Manager) DestinationRecords() []*DestinationRecord {
	m.destMu.Lock()
	defer m.destMu.Unlock()

	records := make([]*DestinationRecord, 0, len(m.destRecords))
	for _, record := range m.destRecords {
		entry := *record
		records = append(records, &entry)
	}
	return records
}

func (m *Manager) ResetDestinations() {
	m.destMu.Lock()
	m.destRecords = make(map[string]*DestinationRecord)
	m.destMu.Unlock()
}

// RestoreDestinationRecords replaces the in-memory aggregation table with
// records loaded from persistent storage.
func (m *Manager) RestoreDestinationRecords(records map[string]*DestinationRecord) {
	m.destMu.Lock()
	m.destRecords = make(map[string]*DestinationRecord, len(records))
	for key, record := range records {
		m.destRecords[key] = record
	}
	m.destMu.Unlock()
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

// StartAutoSave runs saveFn on every interval tick until StopAutoSave.
func (m *Manager) StartAutoSave(interval time.Duration, saveFn func()) {
	m.StopAutoSave()
	m.saveFn = saveFn
	m.saveTicker = time.NewTicker(interval)
	m.saveDone = make(chan struct{})
	go func() {
		for {
			select {
			case <-m.saveTicker.C:
				if m.saveFn != nil {
					m.saveFn()
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
