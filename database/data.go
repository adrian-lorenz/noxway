package database

import (
	"errors"
	"log"
	"os"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB = nil

type ConfigEntry struct {
	Key   string `gorm:"primaryKey;size:100"`
	Value string `gorm:"type:text"`
}

func ConnectDB() error {
	db, err := gorm.Open(postgres.Open(os.Getenv("DATABASE")), &gorm.Config{})
	if err != nil {
		log.Println("database connection error:", err)
		return errors.New("can't connect to database")
	}
	if err := db.AutoMigrate(&Logtable{}, &ConfigEntry{}); err != nil {
		return err
	}
	DB = db
	return nil
}

func LoadConfigEntry(key string) (string, error) {
	if DB == nil {
		return "", errors.New("database not initialized")
	}
	var entry ConfigEntry
	if err := DB.First(&entry, "key = ?", key).Error; err != nil {
		return "", err
	}
	return entry.Value, nil
}

func SaveConfigEntry(key, value string) error {
	if DB == nil {
		return errors.New("database not initialized")
	}
	entry := ConfigEntry{Key: key, Value: value}
	return DB.Save(&entry).Error
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
		subQuery := DB.Model(&Logtable{}).Select("id").Order("created ASC").Limit(int(deleteCount))
		if err := DB.Where("id IN (?)", subQuery).Delete(&Logtable{}).Error; err != nil {
			return err
		}
		log.Printf("Cleaned up %d old log entries", deleteCount)
	}
	return nil
}

// DeleteLogsOlderThan deletes all log entries older than the given retention duration.
func DeleteLogsOlderThan(retention time.Duration) error {
	if DB == nil {
		return errors.New("database not initialized")
	}
	cutoff := time.Now().Add(-retention)
	result := DB.Where("created < ?", cutoff).Delete(&Logtable{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		log.Printf("Retention cleanup: deleted %d log entries older than %v", result.RowsAffected, retention)
	}
	return nil
}

// StartCleanupRoutine starts a background goroutine that periodically cleans up old logs.
// maxEntries: hard cap on total row count (0 = disabled)
// retention: delete entries older than this duration (0 = disabled)
func StartCleanupRoutine(maxEntries int, retention time.Duration, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if retention > 0 {
				if err := DeleteLogsOlderThan(retention); err != nil {
					log.Printf("Retention cleanup failed: %v", err)
				}
			}
			if maxEntries > 0 {
				if err := CleanupOldLogs(maxEntries); err != nil {
					log.Printf("Log cleanup failed: %v", err)
				}
			}
		}
	}()
	log.Printf("Started log cleanup routine (max %d entries, retention %v, every %v)", maxEntries, retention, interval)
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
