package model

type Category struct {
	Id     int         `json:"id"`
	Name   string      `json:"name"`
	Parent interface{} `json:"parent"`
}