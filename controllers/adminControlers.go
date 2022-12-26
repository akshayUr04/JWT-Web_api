package controllers

import (
	"fmt"
	"net/http"
	"os"
	"time"
	"web-api/intializers"
	"web-api/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func AdminSignup(c *gin.Context) {

	//creating a variable to store the data given by user
	var body struct {
		Name     string
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}
	//Binding datas to created bidy
	err := c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}

	// Hashing the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "failed to hash password",
		})
		return
	}
	//Create admin
	admin := models.Admin{Name: body.Name, Email: body.Email, Password: string(hash)}
	result := intializers.DB.Create(&admin) // pass pointer of data to Create

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "failed to create user",
		})
		return
	}

	// fmt.Println(result.Error)

	//respond
	c.JSON(http.StatusOK, gin.H{
		"message": "admin created",
	})

}

func AdminLogin(c *gin.Context) {
	//Get name email password

	var body struct {
		Name     string
		Email    string
		Password string
	}
	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "faild to get body",
		})
		return
	}

	//Look for requested adimn with the email and name
	var admin models.Admin
	intializers.DB.Where("name = ? AND  email= ?", body.Name, body.Email).Find(&admin)

	if admin.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "Inavlid name or email",
		})
		return
	}
	// Compare sent in password with hashed password in the db
	err = bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	//create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": admin.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	fmt.Println(token)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECERET")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	//sent it back

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "cookie is created",
	})

}

func AdminValidate(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "admin validated",
	})
}

func AdminLogout(c *gin.Context) {

	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	c.SetCookie("Authorization", "", -1, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
}

func FindALl(c *gin.Context) {
	var users []models.User
	result := intializers.DB.Find(&users)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No users found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": users,
	})

}

func FindUsers(c *gin.Context) {

	//geting username and email

	var body struct {
		Name  string
		Email string
	}

	err := c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "failed to read body",
		})
		return
	}

	var user models.User
	intializers.DB.Where("name = ? AND email = ?", body.Name, body.Email).Find(&user)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "no user found",
		})
		return
	} else {
		c.JSON(http.StatusOK, gin.H{
			"message": user,
		})
	}

}

func DeleteUser(c *gin.Context) {
	var body struct {
		Name  string
		Email string
	}

	err := c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "failed to read body",
		})
		return
	}

	var user models.User
	intializers.DB.Where("name = ? AND email= ?", body.Name, body.Email).Delete(&user)

	// if user.ID == 0 {
	// 	c.JSON(http.StatusBadRequest, gin.H{
	// 		"err": "No user found",
	// 	})
	// 	return
	// }

	c.JSON(http.StatusOK, gin.H{
		"message": "user deleted",
	})

}

func CreateUser(c *gin.Context) {

	//get the values
	var body struct {
		Name     string
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	err := c.Bind(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "filed to read body",
		})
		return
	}

	//hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"err": "failed to hash password",
		})
		return
	}

	//create user
	user := models.User{Name: body.Name, Email: body.Email, Password: string(hash)} //the hash is in byte type so converting it into string
	result := intializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "failed to create user",
		})
		return
	}

	//respond
	c.JSON(http.StatusOK, gin.H{
		"message": "user created",
	})
}

func UpdateUser(c *gin.Context) {

	var body struct {
		Email string

		New_password string //`json:"password" binding:"required,min=6"`
	}
	err := c.Bind(&body)
	fmt.Println(err)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "error to bind body",
		})
		return
	}

	// hash the pawssrod

	hash, err := bcrypt.GenerateFromPassword([]byte(body.New_password), 10)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "failed to hash password",
		})
	}
	// user := models.User{Name: body.New_name, Email: body.New_email, Password: string(hash)}
	// result := intializers.DB.Model(&user).Where("email=?", body.Email).Update("password", string(hash))
	// if result.Error != nil {
	// }

	// intializers.DB.Model(&user).Where("email=?", body.Email).Update("password", body.New_email)
	// intializers.DB.Model(&user).Where("name = ? AND email=?", body.Name, body.Email).Select("name", "email").Update(User{Name: body.New_name, Email: body.New_email, Password: string(hash)})

	user := models.User{Password: string(hash)}

	result := intializers.DB.Model(&user).Where("email=?", body.Email).Update("password", string(hash))

	fmt.Println(result)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to update password",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "successfully changed password",
	})
}
