package db

type DBService interface {
	Close() error

	GetAllCategories() (*Category, error)
	GetProductsById(string) (*Category, error)
}
