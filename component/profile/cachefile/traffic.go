package cachefile

import (
	"encoding/binary"
	"os"
	"sort"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
	"github.com/vmihailenco/msgpack/v5"
)

// DestinationRecord stores the aggregated traffic of one destination & process.
type DestinationRecord struct {
	Host          string    `json:"host"`
	Process       string    `json:"process"`
	VisitCount    int64     `json:"visitCount"`
	UploadTotal   int64     `json:"uploadTotal"`
	DownloadTotal int64     `json:"downloadTotal"`
	LastSeen      time.Time `json:"lastSeen"`
}

func (c *CacheFile) trafficDBView(fn func(tx *bbolt.Tx) error) error {
	if c.trafficDB != nil {
		return c.trafficDB.View(fn)
	}
	if c.DB == nil {
		return nil
	}
	return c.DB.View(fn)
}

func (c *CacheFile) trafficDBBatch(fn func(tx *bbolt.Tx) error) error {
	if c.trafficDB != nil {
		return c.trafficDB.Batch(fn)
	}
	if c.DB == nil {
		return nil
	}
	return c.DB.Batch(fn)
}

func (c *CacheFile) InitTrafficDB(path string) error {
	if c.trafficDB != nil {
		c.trafficDB.Close()
		c.trafficDB = nil
	}

	if path == "" {
		path = C.Path.Resolve("traffic.db")
	}

	options := bbolt.Options{Timeout: time.Second, NoStatistics: true}
	db, err := bbolt.Open(path, os.FileMode(0o666), &options)
	if err != nil {
		log.Warnln("[CacheFile] can't open traffic db file %s: %s", path, err.Error())
		return err
	}

	c.trafficDB = db
	c.trafficDBPath = path
	log.Infoln("[CacheFile] traffic db initialized at %s", path)
	return nil
}

func (c *CacheFile) CloseTrafficDB() {
	if c.trafficDB != nil {
		c.trafficDB.Close()
		c.trafficDB = nil
	}
}

func (c *CacheFile) TrafficDBPath() string {
	return c.trafficDBPath
}

func (c *CacheFile) StoreCumulativeTraffic(upload, download int64) {
	err := c.trafficDBBatch(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketTraffic)
		if err != nil {
			return err
		}
		buf := make([]byte, 16)
		binary.BigEndian.PutUint64(buf[:8], uint64(upload))
		binary.BigEndian.PutUint64(buf[8:16], uint64(download))
		return bucket.Put([]byte("cumulative"), buf)
	})
	if err != nil {
		log.Warnln("[CacheFile] store cumulative traffic failed: %s", err.Error())
	}
}

func (c *CacheFile) LoadCumulativeTraffic() (upload, download int64) {
	err := c.trafficDBView(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketTraffic)
		if bucket == nil {
			return nil
		}
		data := bucket.Get([]byte("cumulative"))
		if data == nil || len(data) < 16 {
			return nil
		}
		upload = int64(binary.BigEndian.Uint64(data[:8]))
		download = int64(binary.BigEndian.Uint64(data[8:16]))
		return nil
	})
	if err != nil {
		log.Warnln("[CacheFile] load cumulative traffic failed: %s", err.Error())
	}
	return
}

// StoreDestinationRecords persists the destination aggregation table.
// maxRecords <= 0 means unlimited, no eviction is triggered.
func (c *CacheFile) StoreDestinationRecords(records map[string]*DestinationRecord, maxRecords int) {
	if len(records) == 0 {
		return
	}

	err := c.trafficDBBatch(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(bucketTrafficDest)
		if err != nil {
			return err
		}

		// evict the eldest records when exceeding the cap
		if maxRecords > 0 && len(records) > maxRecords {
			keys := make([]string, 0, len(records))
			for key := range records {
				keys = append(keys, key)
			}
			sort.Slice(keys, func(i, j int) bool {
				return records[keys[i]].LastSeen.Before(records[keys[j]].LastSeen)
			})
			for _, key := range keys[:len(keys)-maxRecords] {
				delete(records, key)
			}
		}

		for key, record := range records {
			if record.LastSeen.IsZero() {
				record.LastSeen = time.Now()
			}
			payload, err := msgpack.Marshal(record)
			if err != nil {
				return err
			}
			if err := bucket.Put([]byte(key), payload); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		log.Warnln("[CacheFile] store destination records failed: %s", err.Error())
	}
}

// LoadDestinationRecords loads the destination aggregation table.
// maxRecords <= 0 means unlimited, otherwise the oldest entries are trimmed.
func (c *CacheFile) LoadDestinationRecords(maxRecords int) map[string]*DestinationRecord {
	records := make(map[string]*DestinationRecord)
	err := c.trafficDBView(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketTrafficDest)
		if bucket == nil {
			return nil
		}
		cursor := bucket.Cursor()
		for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
			var record DestinationRecord
			if err := msgpack.Unmarshal(value, &record); err != nil {
				continue
			}
			records[string(key)] = &record
		}
		return nil
	})
	if err != nil {
		log.Warnln("[CacheFile] load destination records failed: %s", err.Error())
	}

	if maxRecords > 0 && len(records) > maxRecords {
		keys := make([]string, 0, len(records))
		for key := range records {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			return records[keys[i]].LastSeen.Before(records[keys[j]].LastSeen)
		})
		for _, key := range keys[:len(keys)-maxRecords] {
			delete(records, key)
		}
	}
	return records
}

// ClearDestinationRecords wipes the destination aggregation table.
func (c *CacheFile) ClearDestinationRecords() {
	err := c.trafficDBBatch(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(bucketTrafficDest)
		if bucket == nil {
			return nil
		}
		return tx.DeleteBucket(bucketTrafficDest)
	})
	if err != nil {
		log.Warnln("[CacheFile] clear destination records failed: %s", err.Error())
	}
}
