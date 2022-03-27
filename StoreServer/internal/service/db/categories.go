package db

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"strconv"
	"time"
)

type Category struct {
	Id            int           `bson:"id"`
	Name          string        `bson:"name"`
	SubCategories []SubCategory `bson:"childCategories"`
	Products      []Product     `bson:"products"`
}

type SubCategory struct {
	Id   int    `bson:"id"`
	Name string `bson:"name"`
}

type Product struct {
	Id       int    `bson:"id"`
	Name     string `bson:"name"`
	ImageUrl string `bson:"image"`
	Price    string `bson:"price"`
}

func (m *MongoCon) GetAllCategories() (*Category, error) {
	ctx, cancel := context.WithTimeout(m.mongoConnCtx, time.Second*10)
	defer cancel()
	coll := m.mongoConn.Database("ShopRaspredel").Collection("Categories")
	var response Category
	err := coll.FindOne(ctx, bson.M{}).Decode(&response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

func (m *MongoCon) GetProductsById(id string) (*Category, error) {
	ctx, cancel := context.WithTimeout(m.mongoConnCtx, time.Second*10)
	defer cancel()
	coll := m.mongoConn.Database("ShopRaspredel").Collection("Categories")
	if id == "other" {

	}
	idx, _ := strconv.Atoi(id)
	var responseMongo Category
	err := coll.FindOne(ctx, bson.D{{"id", idx}}).Decode(&responseMongo)
	if err != nil {
		return nil, err
	}

	return &responseMongo, nil
}
