package database

import (
	"errors"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB = nil

func ConnectDB(rootpath string) error {
	dbfile := filepath.Join(rootpath, "database", "database.db")
	db, err := gorm.Open(sqlite.Open(dbfile), &gorm.Config{})
	if err != nil {
		log.Error(err)
		return errors.New("can't connect to database")
	}
	errCre := db.AutoMigrate(&Logtable{})
	if errCre != nil {
		return errCre
	}

	DB = db
	return nil
}

type Logtable struct {
	ID      uint   `gorm:"primaryKey"`
	GUID    string `gorm:"size:100"`
	IP      string `gorm:"size:100"`
	Path    string `gorm:"size:255"`
	Service string `gorm:"size:100"`
	ServiceExists bool
	HeaderRouting bool
	EndPoint string `gorm:"size:255"`
	Method  string `gorm:"size:100"`
	RequestSize int 
	Host	string `gorm:"size:100"`
	HeadersCount int
	ResponseTime float32 
	StatusCode int
	
	Created time.Time `gorm:"autoCreateTime"`
	Message string 
}
