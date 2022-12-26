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

func UserSignUp(c *gin.Context) {

	// get all elements from the user
	var body struct {
		Name     string
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	err := c.Bind(&body)

	fmt.Println(err)
	if err != nil {
		c.JSON(http.StatusBadRequest, err.Error())
		return
	}

	//hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed hash password",
		})
		return
	}

	// create user
	user := models.User{Name: body.Name, Email: body.Email, Password: string(hash)} //the hash is in byte type so converting it into string
	result := intializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed create user",
		})
		return
	}
	//respond
	c.JSON(http.StatusOK, gin.H{
		"message": "user created",
	})
}

func UserLogin(c *gin.Context) {
	//Get name email password

	var body struct {
		Name     string
		Email    string
		Password string
	}

	err := c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "failed to read a body",
		})
		return
	}

	//Look for requested user with the email and name

	var user models.User
	intializers.DB.Where("name = ? AND  email= ?", body.Name, body.Email).Find(&user)

	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	//compare and sent the password  that is hashed

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	//Generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

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
		"message": "cookie is createsd",
	})

}

func UserValidate(c *gin.Context) {

	c.JSON(http.StatusOK, gin.H{
		"message": "user validated",
	})
}

func UserLogout(c *gin.Context) {

	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	c.SetCookie("Authorization", "", -1, "", "", false, true)
	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
}
