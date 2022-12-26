package models

import "gorm.io/gorm"

type Admin struct {
	gorm.Model

	Name     string
	Email    string `gorm:"unique"`
	Password string
}
