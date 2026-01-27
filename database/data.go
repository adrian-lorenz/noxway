package database

import (
	"errors"
	"os"
	"time"

	"github.com/adrian-lorenz/noxway/global"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB = nil

func ConnectDB(rootpath string) error {
	db, err := gorm.Open(mysql.Open(os.Getenv("DATABASE")), &gorm.Config{})
	if err != nil {
		global.Log.Error(err)
		return errors.New("can't connect to database")
	}
	errCre := db.AutoMigrate(&Logtable{})
	if errCre != nil {
		return errCre
	}

	DB = db
	return nil
}

// CleanupOldLogs deletes oldest entries when count exceeds maxEntries
func CleanupOldLogs(maxEntries int) error {
	if DB == nil {
		return errors.New("database not initialized")
	}

	var count int64
	if err := DB.Model(&Logtable{}).Count(&count).Error; err != nil {
		return err
	}

	if count > int64(maxEntries) {
		deleteCount := count - int64(maxEntries)
		// Delete oldest entries by selecting the oldest IDs
		subQuery := DB.Model(&Logtable{}).Select("id").Order("created ASC").Limit(int(deleteCount))
		if err := DB.Where("id IN (?)", subQuery).Delete(&Logtable{}).Error; err != nil {
			return err
		}
		global.Log.Infof("Cleaned up %d old log entries", deleteCount)
	}
	return nil
}

// StartCleanupRoutine starts a background goroutine that periodically cleans up old logs
func StartCleanupRoutine(maxEntries int, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := CleanupOldLogs(maxEntries); err != nil {
				global.Log.Errorf("Log cleanup failed: %v", err)
			}
		}
	}()
	global.Log.Infof("Started log cleanup routine (max %d entries, every %v)", maxEntries, interval)
}

type Logtable struct {
	ID            uint   `gorm:"primaryKey"`
	GUID          string `gorm:"size:100"`
	IP            string `gorm:"size:100"`
	Path          string `gorm:"size:255"`
	Service       string `gorm:"size:100"`
	ServiceExists bool
	HeaderRouting bool
	Routed        bool
	EndPoint      string `gorm:"size:255"`
	Method        string `gorm:"size:100"`
	RequestSize   int
	Host          string `gorm:"size:100"`
	HeadersCount  int
	ResponseTime  float32
	StatusCode    int
	Created       time.Time `gorm:"autoCreateTime"`
	Message       string
	TimePre       float32
	TimePost      float32
	TimeFull      float32
}
