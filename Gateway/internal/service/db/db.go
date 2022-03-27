package db

type DBService interface {
	Close() error

	// User methods
	AddUser(User) (string, error)
	GetUser(string) (*User, error)
	SetRoleForUser(string, string) error
	GetRoleByUserID(int) (int, error)
}
