+++ 
tags = ["ctf","crypto","integer-handling"] 
categories = ["CTF Writeups", "Cryptography"] 
date = "2023-1-6" 
description = "An easy 'crypto' challenge where we can trick a casino into adding to our balance by betting a negative amount of money." 
title = "TetCTF 2022: casino"
+++

# Overview

`casino` was an easy 'crypto' challenge from TetCTF 2023, written by `ndh`.
The description is as follows:
> Not really crypto...

The idea of the challenge is to beat a casino and get enough money that your balance as bytes is longer (or equal to) the length of the flag. The challenge is written in `go`, the source is pasted below.

{{< code language="go" title="main.go" id="1" expand="Show" collapse="Hide" isCollapsed="true" >}}
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
)

type Request struct {
	Recipient string `json:"recipient"`
	Command   string `json:"command"`

	// | recipient  | command              | username | amount | n | balance | proof_data |
	// |------------|----------------------|----------|--------|---|---------|------------|
	// | FlagSeller | PrintFlag            |    x     |        |   |    x    |     x      |
	// | Casino     | Register             |    x     |        |   |         |            |
	// | Casino     | Bet                  |    x     |   x    | x |         |            |
	// | Casino     | ShowBalanceWithProof |    x     |        |   |         |            |

	Username  string   `json:"username"`
	Amount    *big.Int `json:"amount"`
	N         int      `json:"n"`
	Balance   *big.Int `json:"balance"`
	ProofData []byte   `json:"proof_data"`
}

func main() {
	flag, err := os.ReadFile("flag")
	if err != nil {
		log.Fatal(err)
	}
	casino := NewCasino()
	flagSeller := NewFlagSeller(casino.RetrieveRootHash, string(flag))

	var request Request
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		if err := json.Unmarshal(line, &request); err != nil {
			fmt.Printf("Cannot read request: %s\n", err)
			continue
		}
		switch request.Recipient {
		case "Casino":
			switch request.Command {
			case "Register":
				if err := casino.Register(request.Username); err != nil {
					fmt.Printf("An error occured: %s\n", err)
					continue
				}
			case "Bet":
				if err := casino.Bet(request.Username, request.Amount, request.N); err != nil {
					fmt.Printf("An error occured: %s\n", err)
					continue
				}
			case "ShowBalanceWithProof":
				if err := casino.ShowBalanceWithProof(request.Username); err != nil {
					fmt.Printf("An error occured: %s\n", err)
					continue
				}
			default:
				fmt.Printf("Unknown command: %s\n", request.Command)
				continue
			}
		case "FlagSeller":
			switch request.Command {
			case "PrintFlag":
				if err := flagSeller.PrintFlag(request.Username, request.Balance, request.ProofData); err != nil {
					fmt.Printf("An error occured: %s\n", err)
					continue
				}
			default:
				fmt.Printf("Unknown command: %s\n", request.Command)
				continue
			}

		default:
			fmt.Printf("Unknown recipient: %s\n", request.Recipient)
			continue
		}
	}
}
{{< /code >}}

{{< code language="go" title="casino.go" id="2" expand="Show" collapse="Hide" isCollapsed="true" >}}
package main

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cosmos/iavl"
	db "github.com/tendermint/tm-db"
	"log"
	"math/big"
	"math/rand"
)

type Casino struct {
	tree        *iavl.MutableTree
	numAccounts int
}

func NewCasino() *Casino {
	tree, err := iavl.NewMutableTree(db.NewMemDB(), 128, true)
	if err != nil {
		log.Fatal(err)
	}
	tmp := make([]byte, 8)
	if _, err = cryptorand.Read(tmp); err != nil {
		log.Fatal(err)
	}
	rand.Seed(int64(binary.LittleEndian.Uint64(tmp)))
	return &Casino{
		tree:        tree,
		numAccounts: 0,
	}
}

func (c *Casino) getBalance(username string) (*big.Int, error) {
	value, err := c.tree.Get([]byte(username))
	if err != nil {
		log.Fatal(err)
	}
	if value == nil {
		return nil, errors.New("player-not-exist")
	}
	return new(big.Int).SetBytes(value), nil
}

func (c *Casino) setBalance(username string, value *big.Int) {
	_, err := c.tree.Set([]byte(username), value.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	_, _, err = c.tree.SaveVersion()
	if err != nil {
		log.Fatal(err)
	}
}

const MaxPlayers = 100
const InitialBalance = 2023

func (c *Casino) Register(username string) error {
	exist, err := c.tree.Has([]byte(username))
	if err != nil {
		log.Fatal(err)
	}
	if exist {
		return errors.New("player-exists")
	}
	if c.numAccounts >= MaxPlayers {
		return errors.New("max-players")
	}
	c.numAccounts += 1
	c.setBalance(username, big.NewInt(InitialBalance))
	fmt.Printf("Added user: %s.\n", username)
	return nil
}

func (c *Casino) Bet(username string, amount *big.Int, n int) error {
	currentBalance, err := c.getBalance(username)
	if err != nil {
		return err
	}
	if currentBalance.Cmp(amount) < 0 {
		return errors.New("insufficient-balance")
	}
	r := rand.Intn(2023)
	if r == n { // correct guess
		reward := new(big.Int).Mul(amount, big.NewInt(2022))
		currentBalance.Add(currentBalance, reward)
		c.setBalance(username, currentBalance)
		fmt.Printf("YOU WIN! Current balance: %d (+%d).\n", currentBalance, reward)
	} else {
		currentBalance.Sub(currentBalance, amount)
		c.setBalance(username, currentBalance)
		fmt.Printf("YOU LOSE (%d != %d)! Current balance: %d (-%d).\n", r, n, currentBalance, amount)
	}
	return nil
}

func (c *Casino) ShowBalanceWithProof(username string) error {
	value, proof, err := c.tree.GetWithProof([]byte(username))
	if err != nil {
		log.Fatal(err)
	}
	if value == nil {
		return errors.New("player-not-exist")
	}
	proofData, err := proof.ToProto().Marshal()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%d, %s\n", new(big.Int).SetBytes(value), base64.StdEncoding.EncodeToString(proofData))
	return nil
}

func (c *Casino) RetrieveRootHash() []byte {
	result, err := c.tree.Hash()
	if err != nil {
		log.Fatal(err)
	}
	return result
}
{{< /code >}}

{{< code language="go" title="flag_seller.go" id="3" expand="Show" collapse="Hide" isCollapsed="true" >}}
package main

import (
	"fmt"
	"github.com/cosmos/iavl"
	iavlproto "github.com/cosmos/iavl/proto"
	"github.com/golang/protobuf/proto"
	"math/big"
)

type FlagSeller struct {
	dbRootRetriever func() []byte
	flag            string
}

func NewFlagSeller(dbRootRetriever func() []byte, flag string) *FlagSeller {
	return &FlagSeller{
		dbRootRetriever: dbRootRetriever,
		flag:            flag,
	}
}

func (fs *FlagSeller) PrintFlag(usename string, balance *big.Int, proofData []byte) error {
	var pbProof iavlproto.RangeProof
	if err := proto.Unmarshal(proofData, &pbProof); err != nil {
		return fmt.Errorf("bad proof format: %w", err)
	}
	proof, err := iavl.RangeProofFromProto(&pbProof)
	if err != nil {
		return fmt.Errorf("bad proof format: %w", err)
	}
	if err := proof.Verify(fs.dbRootRetriever()); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}
	if err := proof.VerifyItem([]byte(usename), balance.Bytes()); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	l := balance.BitLen() / 8
	dot3 := "..."
	if l >= len(fs.flag) {
		l = len(fs.flag)
		dot3 = ""
	}
	fmt.Printf("Your flag is: %s%s\n", fs.flag[:l], dot3)
	return nil
}
{{< /code >}}

I admit, I actually couldn't spot the bug here until `casino2` was released. When the sequel dropped, I diffed the two challenges to find one small difference:

```diff
diff casino/casino/casino.go casino2/casino.go
83a84
>       amount.Abs(amount)
```

In the second challenge, the absolute value function is used on the amount we bet, meaning the amount always will be positive, however, this is omitted in the first challenge. There is a check to make sure our balance is greater than the amount we bet, to stop us from betting too much...
```go
if currentBalance.Cmp(amount) < 0 {
		return errors.New("insufficient-balance")
	}
```
...but this check does not prevent us from providing a negative bet amount, which is of course less than our current balance! If we specify a negative amount and then lose, the program will subtract a negative number from our balance, which will actually add to the balance. We can specify a hugely negative number, verify our balance, and then request the flag to solve the challenge. My solution in python is below.

{{< code language="python" title="x.py" id="4" expand="Show" collapse="Hide" isCollapsed="false" >}}
from pwn import *
from json import loads, dumps

r = remote("192.53.115.129",31338)
r.sendline(dumps({"recipient":"Casino","command":"Register","username":"toast"}).encode('utf-8'))
r.sendline(dumps({"recipient":"Casino","command":"Bet","username":"toast","amount":-999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999,"n":1}).encode('utf-8'))
r.sendline(dumps({"recipient":"Casino","command":"ShowBalanceWithProof","username":"toast"}).encode('utf-8'))
r.recvline()
r.recvline()
data = r.recvline().decode()
balance = int(data.split(",")[0])
proof = data.split(",")[1].strip()
log.success(f"Balance: {balance}")
r.sendline(dumps({"recipient":"FlagSeller","command":"PrintFlag","username":"toast","balance":balance,"proof_data":proof}).encode('utf-8'))
r.interactive()
{{< /code >}}
