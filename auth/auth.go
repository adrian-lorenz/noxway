package auth

import (
	"encoding/json"
	"errors"
	"os"

	"golang.org/x/crypto/bcrypt"
)

type AuthStruct struct {
	Users         []User   `json:"users"`

}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role string `json:"role"`
	Service string `json:"service"`
}

func LoadConfig(path string) (*AuthStruct, error) {
	var config AuthStruct
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
func MarshalConfig(config AuthStruct) ([]byte, error) {
	return json.MarshalIndent(config, "", "  ")
}


func AddUser(config *AuthStruct, user User, userType string, service string) error {
	if user.Username == "" || user.Password == "" || userType == ""{
		return errors.New("username and password are required")
	}
	//hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashedPassword)
	switch userType {
	case "admin":
		user.Role = "admin"
		config.Users = append(config.Users, user)
	case "viewer":
		user.Role = "viewer"
		config.Users = append(config.Users, user)
	case "basic":
		if service == "" {
			return errors.New("service is required for basic auth user")
		}
		user.Role = "basic"
		user.Service = service
		config.Users = append(config.Users, user)
	}
	return nil
}

func RemoveUser(config *AuthStruct, username string, userType string) error {
	if username == "" || userType == ""{
		return errors.New("username and userType are required")
	}
	for i, user := range config.Users {
		if user.Username == username && user.Role == userType {
			config.Users = append(config.Users[:i], config.Users[i+1:]...)
			return nil
		}
	}

	return errors.New("user not found")
}


