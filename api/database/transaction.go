package database

import (
	"encoding/base64"
	"errors"
	"fmt"
	m "govulnapi/models"
	"strconv"
	"strings"
	"time"
)

func (d *DB) AddTransaction(senderId int, coinId string, address string, qty float64, note string) error {
	user, err := d.GetUserById(senderId)
	if err != nil {
		return err
	}

	var senderBalance m.CoinBalance
	for _, balance := range user.CoinBalances {
		if balance.CoinId == coinId {
			senderBalance = balance
			break
		}
	}

	// Read address info
	receiverByte, err := base64.StdEncoding.DecodeString(address)
	if err != nil {
		return errors.New("Invalid address encoding!")
	}
	receiver := strings.Split(string(receiverByte), "-")
	if len(receiver) < 3 {
		return errors.New("Invalid address format!")
	}
	receiverCoinId := receiver[0]
	receiverId, err := strconv.Atoi(receiver[2])
	if err != nil {
		return errors.New("Invalid receiver ID in address!")
	}

	if coinId != receiverCoinId {
		return errors.New("Address not compatible with selected coin!")
	}

	if receiverId == user.Id {
		return errors.New("Can't send coins to your your own account!")
	}

	if senderBalance.CoinId == "" {
		return errors.New("Coin with requested id doesn't exist!")
	}

	if qty <= 0 {
		return errors.New("Quantity needs to be > 0!")
	}

	if senderBalance.Qty < qty {
		return errors.New("Not enough coin!")
	}

	// CWE-89:  SQL Injection - FIXED: Use parameterized queries and standard identifier quoting
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	qBalanceReceiver := "UPDATE coin_balance SET qty=qty+? WHERE address=?"
	r, err := tx.Exec(qBalanceReceiver, qty, address)
	if err != nil {
		return err
	}
	rows, _ := r.RowsAffected()
	if rows == 0 {
		return errors.New("Receiver address doesn't exist!")
	}

	qBalanceSender := "UPDATE coin_balance SET qty=qty-? WHERE address=?"
	if _, err = tx.Exec(qBalanceSender, qty, senderBalance.Address); err != nil {
		return err
	}

	qTransaction := "INSERT INTO transaction (sender_id,receiver_id,coin_id,address,qty,date,note) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err = tx.Exec(qTransaction, user.Id, receiverId, coinId, address, qty, time.Now(), note); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	return nil
}
