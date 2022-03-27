package db

import (
	"context"
	"log"
	"strconv"
)

type User struct {
	Id       int    `json:"-"`
	Login    string `json:"Login"`
	Email    string `json:"Email"`
	Password string `json:"Password"`
}

func (db *PgxCon) AddUser(u User) (string, error) {
	connCtx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	var id int

	_ = db.pgConn.QueryRow(connCtx, "SELECT id from shop_user WHERE id=$1", u.Id).Scan(&id)
	if id != 0 {
		str := strconv.Itoa(id)
		return str, nil
	}

	tx, _ := db.pgConn.Begin(connCtx)
	err := tx.QueryRow(connCtx,
		"INSERT INTO shop_user (login_name,pass_hash,Email) VALUES ($1,$2,$3) returning id",
		u.Login, u.Password, u.Email).Scan(&id)

	if err != nil {
		tx.Rollback(connCtx)
		return "", err
	}

	tx.Commit(connCtx)
	str := strconv.Itoa(id)
	return str, nil
}

func (db *PgxCon) GetUser(login string) (*User, error) {
	var user User
	connCtx, cancel := context.WithTimeout(db.pgConnCtx, waitTimeout)
	defer cancel()
	err := db.pgConn.QueryRow(connCtx, "SELECT id,login_name,pass_hash,email FROM shop_user WHERE login_name=$1", login).
		Scan(&user.Id, &user.Login, &user.Password, &user.Email)
	log.Println(user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *PgxCon) SetRoleForUser(uid string, roleid string) error {
	connCtx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	var roid int

	_ = db.pgConn.QueryRow(connCtx, "SELECT role_id FROM role_users WHERE user_id=$1", uid).Scan(&roid)
	if roid != 0 {
		return nil
	}

	id, _ := strconv.Atoi(uid)
	rid, _ := strconv.Atoi(roleid)
	tx, _ := db.pgConn.Begin(connCtx)
	err := tx.QueryRow(connCtx,
		"INSERT INTO role_users (user_id,role_id) VALUES ($1,$2) returning id",
		id, rid).Scan(&roid)

	if err != nil {
		tx.Rollback(connCtx)
		return err
	}

	tx.Commit(connCtx)
	return nil
}

func (db *PgxCon) GetRoleByUserID(id int) (int, error) {
	var roleID int
	connCtx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()

	err := db.pgConn.QueryRow(connCtx, "SELECT role_id FROM role_users WHERE user_id=$1", id).
		Scan(&roleID)
	log.Println(roleID)
	if err != nil {
		return 0, err
	}
	return roleID, nil
}
