package cachefile

import (
	"encoding/binary"
	"os"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/bbolt"
)

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

	c.trafficDBPath = path

	options := bbolt.Options{Timeout: time.Second, NoStatistics: true}
	db, err := bbolt.Open(path, os.FileMode(0o666), &options)
	if err != nil {
		log.Warnln("[CacheFile] can't open traffic db file %s: %s", path, err.Error())
		return err
	}

	c.trafficDB = db
	log.Infoln("[CacheFile] traffic db initialized at %s", path)
	return nil
}

func (c *CacheFile) TrafficDBPath() string {
	return c.trafficDBPath
}

func (c *CacheFile) CloseTrafficDB() {
	if c.trafficDB != nil {
		c.trafficDB.Close()
		c.trafficDB = nil
	}
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
