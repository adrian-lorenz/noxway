package certs

import (
	"github.com/adrian-lorenz/noxway/global"
	"github.com/adrian-lorenz/noxway/middleware"
	"github.com/adrian-lorenz/noxway/security"
	"github.com/gin-gonic/gin"
)

func RetiveCert(c *gin.Context) {
	if !security.IntJWTCheck(c, "admin") {
		c.AbortWithStatus(401)
		return
	}
	if !security.CheckWhitelists(middleware.GetIP(c)) {
		global.Log.Errorln("IP not whitelisted")
		c.JSON(403, gin.H{"error": "IP not whitelisted"})
		return
	}
	type request struct {
		Domain string `json:"domain" binding:"required"`
		Mail   string `json:"mail" binding:"required"`
	}
	var r request
	if err := c.ShouldBindJSON(&r); err != nil {
		global.Log.Errorln("Failed to bind request:", err)
		c.JSON(400, gin.H{"error": "Failed to bind request", "message": err.Error()})
		return
	}
	if r.Domain == "" || r.Mail == "" {
		global.Log.Errorln("Domain or Mail is empty")
		c.JSON(400, gin.H{"error": "Domain or Mail is empty"})
		return
	}
	if global.Config.SSLDomain != r.Domain {
		global.Config.SSLDomain = r.Domain
	}
	if global.Config.SSLMail != r.Mail {
		global.Config.SSLMail = r.Mail
	}
	global.SaveGlobalConfig()

	_, _, errC := CertExist(global.Config.SSLDomain)
	if errC == nil {
		global.Log.Infoln("Certificate ok")
		c.JSON(200, gin.H{"message": "Certificate ok"})
		return
	}
	global.Log.Infoln("Certificate not ok")
	dnsCheck, errD := CheckDNS(global.Config.SSLDomain)
	if errD != nil {
		global.Log.Errorln("Failed to check DNS:", errD)
		c.JSON(500, gin.H{"error": "Failed to check DNS", "message": errD.Error()})
		return
	}
	if dnsCheck {
		global.Log.Infoln("DNS ok")
		if global.Config.SSLMail == "" {
			global.Log.Errorln("Mail is empty")
			c.JSON(500, gin.H{"error": "Mail is empty"})
			return
		}
		errR := RetriveCert(global.Config.SSLDomain, global.Config.SSLMail)
		if errR != nil {
			global.Log.Errorln("Failed to retrieve certificate:", errR)
			c.JSON(500, gin.H{"error": "Failed to retrieve certificate", "message": errR.Error()})
			return
		}
		global.Log.Infoln("Certificate created")
		//check if the certificate exists
		cp, kp, errCc := CertExist(global.Config.SSLDomain)
		if errCc != nil {
			global.Log.Errorln("Failed to check certificate:", errCc)
			c.JSON(500, gin.H{"error": "Failed to check certificate", "message": errCc.Error()})
			return
		}
		global.Config.PemCrt = cp
		global.Config.PemKey = kp
		global.SaveGlobalConfig()

		c.JSON(200, gin.H{"message": "cert created"})
		return
	}

}
