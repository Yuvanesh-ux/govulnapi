package database

import (
	"encoding/base64"
	"errors"
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
	receiverByte, _ := base64.StdEncoding.DecodeString(address)
	receiver := strings.Split(string(receiverByte), "-")
	receiverCoinId := receiver[0]
	receiverId, _ := strconv.Atoi(receiver[2])

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

	// CWE-89:  SQL Injection FIXED: Use parameterized queries
	qBalanceReceiver := "UPDATE 'coin_balance' SET qty=qty+? WHERE address=?"
	qBalanceSender := "UPDATE 'coin_balance' SET qty=qty-? WHERE address=?"
	qTransaction := "INSERT INTO 'transaction' (sender_id,receiver_id,coin_id,address,qty,date,note) VALUES (?, ?, ?, ?, ?, ?, ?)"

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	r, err := tx.Exec(qBalanceReceiver, qty, address)
	if err != nil {
		return err
	}
	rows, _ := r.RowsAffected()
	if rows == 0 {
		return errors.New("Receiver address doesn't exist!")
	}

	if _, err = tx.Exec(qBalanceSender, qty, senderBalance.Address); err != nil {
		return err
	}
	if _, err = tx.Exec(qTransaction, user.Id, receiverId, coinId, address, qty, time.Now(), note); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	return nil
}
