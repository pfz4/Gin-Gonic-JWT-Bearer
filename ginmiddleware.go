package jwtbearer

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"strings"
)

func (conf *JwtBearer) LoadJWTBearer() gin.HandlerFunc {
	return func(c *gin.Context) {

		tokenInfo, _ := conf.GetTokenInfoFromAuthHeader(c.Request.Header.Get("Authorization"))
		tokenInfo = conf.ValidateOrigin(tokenInfo, c.Request.Header.Get("Origin"))

		c.Set("tokeninfo", tokenInfo)
		c.Next()
	}
}

func (conf *JwtBearer) RequireJWTBearer() gin.HandlerFunc {
	return func(c *gin.Context) {

		tokenInfo, err := conf.GetTokenInfoFromAuthHeader(c.Request.Header.Get("Authorization"))
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"msg": "The Token is invalid"})
			c.Abort()
			return
		}
		if !tokenInfo.IsValid {
			c.JSON(http.StatusForbidden, gin.H{"msg": tokenInfo.ErrorMessage})
			c.Abort()
			return 
		}
		tokenInfo = conf.ValidateOrigin(tokenInfo, c.Request.Header.Get("Origin"))
		if !tokenInfo.IsValid {
			c.JSON(http.StatusForbidden, gin.H{"msg": tokenInfo.ErrorMessage})
			c.Abort()
			return 
		}

		c.Set("tokeninfo", tokenInfo)
		c.Next()
	}
}

func (conf *JwtBearer) RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {

		tokenInfo, err := conf.GetTokenInfoFromAuthHeader(c.Request.Header.Get("Authorization"))
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"msg": "The Token is invalid"})
			c.Abort()
			return
		}
		if !tokenInfo.IsValid {
			c.JSON(http.StatusForbidden, gin.H{"msg": tokenInfo.ErrorMessage})
			c.Abort()
			return 
		}
		tokenInfo = conf.ValidateOrigin(tokenInfo, c.Request.Header.Get("Origin"))
		if !tokenInfo.IsValid {
			c.JSON(http.StatusForbidden, gin.H{"msg": tokenInfo.ErrorMessage})
			c.Abort()
			return 
		}
		if !sliceContainsValue(strings.Split(tokenInfo.Scope, " "), scope) {
			c.JSON(http.StatusForbidden, gin.H{"msg": "Required Scope not found"})
			c.Abort()
			return 
		}

		c.Set("tokeninfo", tokenInfo)
		c.Next()
	}
}

func (conf *JwtBearer) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {

		tokenInfo, err := conf.GetTokenInfoFromAuthHeader(c.Request.Header.Get("Authorization"))
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"msg": "The Token is invalid"})
			c.Abort()
			return
		}
		if !tokenInfo.IsValid {
			c.JSON(http.StatusForbidden, gin.H{"msg": tokenInfo.ErrorMessage})
			c.Abort()
			return 
		}
		tokenInfo = conf.ValidateOrigin(tokenInfo, c.Request.Header.Get("Origin"))
		if !tokenInfo.IsValid {
			c.JSON(http.StatusForbidden, gin.H{"msg": tokenInfo.ErrorMessage})
			c.Abort()
			return 
		}
		if !sliceContainsValue(tokenInfo.Roles, role) {
			c.JSON(http.StatusForbidden, gin.H{"msg": "Required Role not found"})
			c.Abort()
			return 
		}

		c.Set("tokeninfo", tokenInfo)
		c.Next()
	}
}