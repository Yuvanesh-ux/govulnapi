package database

import (
	"errors"
	"fmt"
	m "govulnapi/models"
	"time"
)

func (d *DB) AddOrder(userId int, coinId string, price float64, isBuy bool, qty float64) error {
	user, err := d.GetUserById(userId)
	if err != nil {
		return err
	}

	var (
		orderValue         = qty * price
		newUsdBalance      float64
		currentCoinBalance m.CoinBalance
		newCoinBalance     float64
	)

	for _, c := range user.CoinBalances {
		if c.CoinId == coinId {
			currentCoinBalance = c
		}
	}

	if qty <= 0 {
		return errors.New("Quantity needs to be > 0!")
	}

	if isBuy {
		if user.UsdBalance < orderValue {
			return errors.New("Not enough usd!")
		}
		newUsdBalance = user.UsdBalance - orderValue
		newCoinBalance = currentCoinBalance.Qty + qty
	} else {
		if currentCoinBalance.Qty < qty {
			return errors.New("Not enough coin!")
		}
		newUsdBalance = user.UsdBalance + orderValue
		newCoinBalance = currentCoinBalance.Qty - qty
	}

	qAddOrder := "INSERT INTO 'order' (user_id, coin_id, price, is_buy, qty, date) VALUES (?, ?, ?, ?, ?, ?)"
	qUpdateFiat := "UPDATE 'user' SET usd_balance = ? WHERE id = ?"
	qUpdateCoinBalance := "UPDATE 'coin_balance' SET qty = ? WHERE user_id = ? AND coin_id = ?"

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err = tx.Exec(qAddOrder, user.Id, coinId, price, isBuy, qty, time.Now()); err != nil {
		return err
	}
	if _, err = tx.Exec(qUpdateFiat, newUsdBalance, user.Id); err != nil {
		return err
	}
	if _, err = tx.Exec(qUpdateCoinBalance, newCoinBalance, user.Id, coinId); err != nil {
		return err
	}

	if err = tx.Commit(); err != nil {
		return err
	}

	return nil
}
