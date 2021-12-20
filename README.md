# Gin-Gonic Offline JWT Verification
This Project is a JWTBearer Middleware for Gin-Gonic

## Middlewares
|Name|Description|
|---|---|
|`LoadJWTBearer`|Sets the `tokeninfo` key in the Context without rejecting an invalid Token. (If Token is invalid, `tokeninfo` is set to `nil`)|
|`RequireJWTBearer`|Sets the `tokeninfo` key in the Context, rejects the request when the Token is invalid|
|`RequireScope`|Sets the `tokeninfo` key in the Context, rejects the request when the Token is invalid, rejects the request when the scope is not in the Token|
|`RequireRole`|Sets the `tokeninfo` key in the Context, rejects the request with a Forbidden when the Token is invalid, rejects the request when the role is not in the Token `roles` Claim|

## Example Usage
```golang
package main
import (
	"gitlab.pfz4.de/pfz4/gin-gonic-jwtbearer"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main(){
	issuer, _ := jwtbearer.GetIssuer("https://example.com/auth/realms/exampleRealm/") //Example URL for Keycloak

	jwtConfig := &jwtBearer.JwtBearer{
		Issuer: issuer,
		Audience: "Testaudience"
	}

	router := gin.Default()
	

	//Works for everyone
	router.GET("/public", 
		jwtConfig.LoadJWTBearer(),
		func(c *gin.Context){
			tokenInfo := c.MustGet("tokeninfo").(jwtbearer.TokenInfo)

			username := "anonymous"
			if tokenInfo != nil{
				username = tokenInfo.Username
			}
			c.String(http.StatusOK, "It Works! @"+username);
		}
	)

	//Only works for logged in users with correct audience
	router.GET("/protected", 
		jwtConfig.RequireJWTBearer(),
		func(c *gin.Context){
			tokenInfo := c.MustGet("tokeninfo").(jwtbearer.TokenInfo)
			c.String(http.StatusOK, "It Works! @"+tokenInfo.Username);
		}
	)

	//Only world for logged in users with role admin and the correct audience
	router.GET("/roleprotected", 
		jwtConfig.RequireRole("admin"),
		func(c *gin.Context){
			tokenInfo := c.MustGet("tokeninfo").(jwtbearer.TokenInfo)
			c.String(http.StatusOK, "It Works! @"+tokenInfo.Username);
		}
	)

	//Only world for logged in users with scope testscope in their token and the correct audience
	router.GET("/scopeprotected", 
		jwtConfig.RequireScope("testscope"),
		func(c *gin.Context){
			tokenInfo := c.MustGet("tokeninfo").(jwtbearer.TokenInfo)
			c.String(http.StatusOK, "It Works! @"+tokenInfo.Username);
		}
	)

	router.Run(":8080")
}
```
