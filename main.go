package main

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type Credentials struct {
	username string
	password string
}

var credentials = []Credentials{
	{username: "anitha", password: "aasadi"},
	{username: "anirudh", password: "ravichandar"},
}

func main() {
	r := gin.Default()

	r.GET("/secure", AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Authenticated successfully!", "data": "sensitive data here"})
	})

	r.Run()
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		decodedBytes, err := base64.StdEncoding.DecodeString(authHeader[len("Basic "):])
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		credentials := string(decodedBytes)

		creds := strings.Split(credentials, ":")
		username := creds[0]
		password := creds[1]

		if !checkCredentials(username, password) {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Next()
	}
}

func checkCredentials(username, password string) bool {
	for _, cred := range credentials {
		if cred.username == username && cred.password == password {
			return true
		}
	}
	return false
}
