package database

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	m "govulnapi/models"
)

func (d *DB) getUser(queryUser string, args ...interface{}) (m.User, error) {
	// This function is inefficient as it fetches all user data
	// (even when not called for), but made this way for simplicity

	// Get user
	var user m.User
	if err := d.db.Get(&user, queryUser, args...); err != nil {
		return m.User{}, err
	}

	// CWE-89:  SQL Injection FIXED: Use parameterized queries for all queries
	qBalances := "SELECT coin_id, address, qty FROM 'coin_balance' WHERE user_id = ?"
	qOrders := "SELECT coin_id, price, is_buy, qty, date FROM 'order' WHERE user_id = ?"
	qTransactions := "SELECT * FROM 'transaction' WHERE sender_id = ? OR receiver_id = ?"

	d.db.Select(&user.CoinBalances, qBalances, user.Id)     // Get user balances
	d.db.Select(&user.Orders, qOrders, user.Id)             // Get user orders
	d.db.Select(&user.Transactions, qTransactions, user.Id, user.Id) // Get user transactions

	return user, nil
}

func (d *DB) GetUserByCredentials(email string, password string) (m.User, error) {
	password = md5sum(password)

	// CWE-89:  SQL Injection FIXED: Use parameterized query
	query := "SELECT * FROM 'user' WHERE user.email = ? and user.password = ?"

	user, err := d.getUser(query, email, password)
	if err != nil {
		return m.User{}, errors.New("No user with matching credentials found!")
	}

	return user, nil
}

func (d *DB) GetUserByEmail(email string) (m.User, error) {
	// CWE-89:  SQL Injection FIXED: Use parameterized query
	query := "SELECT * FROM 'user' WHERE user.email = ?"

	user, err := d.getUser(query, email)
	if err != nil {
		return m.User{}, errors.New("No user with matching email found!")
	}

	return user, nil
}

func (d *DB) GetUserById(userId int) (m.User, error) {
	// CWE-89:  SQL Injection FIXED: Use parameterized query
	query := "SELECT * FROM 'user' WHERE user.id = ?"

	user, err := d.getUser(query, userId)
	if err != nil {
		return m.User{}, errors.New("No user with matching id found!")
	}

	return user, nil
}

func (d *DB) AddUser(email string, password string) error {
	if err := validateEmail(email); err != nil {
		return err
	}

	if _, err := d.GetUserByEmail(email); err == nil {
		return errors.New("Email already registered!")
	}

	// CWE-521: Weak Password Requirements
	if len(password) < 6 {
		return errors.New("Password needs to be at least 6 characters long!")
	}

	hashedPassword := md5sum(password)

	// CWE-89:  SQL Injection FIXED: Use parameterized query
	query := "INSERT INTO 'user' (email, password) VALUES (?, ?)"
	r, err := d.db.Exec(query, email, hashedPassword)
	if err != nil {
		return err
	}
	user_id, _ := r.LastInsertId()

	coins, err := d.GetCoins()
	if err != nil {
		return err
	}

	// Initialize empty balances for every coin
	for _, coin := range coins {
		addressData := fmt.Sprintf("%v-%v-%v", coin.Id, email, user_id)
		address := base64.StdEncoding.EncodeToString([]byte(addressData))

		// CWE-89:  SQL Injection FIXED: Use parameterized query
		query = "INSERT INTO 'coin_balance' (user_id, coin_id, address, qty) VALUES (?, ?, ?, ?)"
		d.db.Exec(query, user_id, coin.Id, address, 0.0)
	}

	// CWE-532: Insertion of Sensitive Information into Log File
	log.Printf("Registered user: email: '%s', password: '%s'\n", email, password)

	return nil
}

func (d *DB) UpdateEmail(userId int, newEmail string) error {
	// if err := validateEmail(newEmail); err != nil {
	// 	return err
	// }

	// CWE-89:  SQL Injection FIXED: Use parameterized query
	query := "UPDATE 'user' SET email=? WHERE id=?"

	_, err := d.db.Exec(query, newEmail, userId)
	if err != nil {
		return err
	}

	// CWE-223: Omission of Security-relevant Information
	log.Println("Updated email for user")
	return nil
}

func (d *DB) UpdatePassword(userId int, newPassword string) error {
	newPassword = md5sum(newPassword)

	// CWE-89:  SQL Injection FIXED: Use parameterized query
	query := "UPDATE 'user' SET password=? WHERE id=?"

	_, err := d.db.Exec(query, newPassword, userId)
	if err != nil {
		return err
	}

	// CWE-778: Insufficient Logging
	// log.Printf("Updated password for user %d\n", userId)
	return nil
}
