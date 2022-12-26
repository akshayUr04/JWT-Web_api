package main

import (
	"web-api/controllers"
	"web-api/intializers"
	"web-api/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	intializers.LoadEnvVariables()
	intializers.ConnectToDB()
	intializers.SyncDatabase()
}
func main() {

	r := gin.Default()

	//User

	r.POST("/usersignup", controllers.UserSignUp)
	r.POST("/userlogin", controllers.UserLogin)
	r.GET("/uservalidate", middleware.RequireAuth, controllers.UserValidate)
	r.POST("/userlogout", controllers.UserLogout)

	//Admin
	r.POST("/adminsignup", controllers.AdminSignup)
	r.POST("/adminlogin", controllers.AdminLogin)
	r.GET("/adminvalidate", middleware.AdminAuth, controllers.AdminValidate)
	r.POST("/adminlogout", controllers.AdminLogout)

	r.GET("/findall", middleware.AdminAuth, controllers.FindALl)
	r.POST("/finduser", middleware.AdminAuth, controllers.FindUsers)
	r.DELETE("/deleteuser", middleware.AdminAuth, controllers.DeleteUser)
	r.POST("/adduser", middleware.AdminAuth, controllers.CreateUser)
	r.PATCH("/updateuser", middleware.AdminAuth, controllers.UpdateUser)

	r.Run()

}
