package testservices

import "github.com/gin-gonic/gin"

func Testservice1(c *gin.Context) {

	c.JSON(200, gin.H{
		"message": "Testservice1",
		"headers": c.Request.Header,
		"ip":      c.ClientIP(),
	})
}

func Testservice2(c *gin.Context) {

	c.JSON(200, gin.H{
		"message": "Testservice2",
		"headers": c.Request.Header,
		"ip":      c.ClientIP(),
	})
}