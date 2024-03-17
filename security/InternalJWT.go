package security

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"os"
)

func IntJWTCheck(c *gin.Context, role string) bool {
	tokenString := c.GetHeader("token")
	if tokenString == "" {

		return false
	}
	//check if the token is valid

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWTSECRET")), nil
	})

	if err != nil || !token.Valid {

		return false
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if claims["role"] == role {
			return true
		}
	}

	return false
}
