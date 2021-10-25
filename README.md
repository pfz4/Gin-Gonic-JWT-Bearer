This Project is a JWTBearer Middleware for Gin-Gonic

# Example Usage
```golang
package main
import (
	"gitlab.pfz4.de/pfz4/gin-gonic-jwtbearer"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main(){
	issuer, _ := jwtbearer.GetIssuer("https://example.com/auth/realms/exampleRealm/") //Example URL for Keycloak

	router := gin.Default()
	
	private := router.Group("/private")
	private.Use(issuer.ValidateToken("DemoAPI"))
	private.GET("/", func(c *gin.Context){
		tokenInfo := c.MustGet("tokeninfo").(jwtbearer.TokenInfo)
		c.String(http.StatusOK, "It Works! @"+tokenInfo.Username);
	})
	public := router.Group("/public")
	public.GET("/", func(c *gin.Context){
		c.String(http.StatusOK, "It Works! @anonymous");
	})
	router.Run(":8080")
}
```