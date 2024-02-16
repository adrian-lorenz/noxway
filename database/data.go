package database

import (
	"api-gateway/global"
	"errors"
	"os"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var DB *gorm.DB = nil

func ConnectDB(rootpath string) error {
	//dbfile := filepath.Join(rootpath, "database", "database.db")
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
