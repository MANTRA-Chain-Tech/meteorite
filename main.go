package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/somatic-labs/meteorite/broadcast"
	"github.com/somatic-labs/meteorite/client"
	"github.com/somatic-labs/meteorite/lib"
	"github.com/somatic-labs/meteorite/types"

	sdkmath "cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

const (
	BatchSize       = 100000000
	TimeoutDuration = 50 * time.Millisecond
)

func main() {
	config := types.Config{}
	if _, err := toml.DecodeFile("nodes.toml", &config); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	mnemonic, err := os.ReadFile("seedphrase")
	if err != nil {
		log.Fatalf("Failed to read seed phrase: %v", err)
	}

	// Set Bech32 prefixes and seal the configuration once
	sdkConfig := sdk.GetConfig()
	sdkConfig.SetBech32PrefixForAccount(config.Prefix, config.Prefix+"pub")
	sdkConfig.SetBech32PrefixForValidator(config.Prefix+"valoper", config.Prefix+"valoperpub")
	sdkConfig.SetBech32PrefixForConsensusNode(config.Prefix+"valcons", config.Prefix+"valconspub")
	sdkConfig.Seal()

	positions := config.Positions
	if positions <= 0 {
		log.Fatalf("Invalid number of positions: %d", positions)
	}
	fmt.Println("Positions", positions)

	var accounts []types.Account
	for i := 0; i < int(positions); i++ {
		position := uint32(i)
		privKey, pubKey, acctAddress := lib.GetPrivKey(config, mnemonic, position)
		accounts = append(accounts, types.Account{
			PrivKey:  privKey,
			PubKey:   pubKey,
			Address:  acctAddress,
			Position: position,
		})
	}

	// **Print addresses and positions at startup**
	fmt.Println("Addresses and Positions:")
	for _, acct := range accounts {
		fmt.Printf("Position %d: Address: %s\n", acct.Position, acct.Address)
	}

	// Get balances and ensure they are within 10% of each other
	balances, err := lib.GetBalances(accounts, config)
	if err != nil {
		log.Fatalf("Failed to get balances: %v", err)
	}

	// Print addresses and balances
	fmt.Println("Wallets and Balances:")
	for _, acct := range accounts {
		balance, err := lib.GetAccountBalance(acct.Address, config)
		if err != nil {
			log.Printf("Failed to get balance for %s: %v", acct.Address, err)
			continue
		}
		fmt.Printf("Position %d: Address: %s, Balance: %s %s\n", acct.Position, acct.Address, balance.String(), config.Denom)
	}

	fmt.Println("balances", balances)

	if !lib.CheckBalancesWithinThreshold(balances, 0.10) {
		fmt.Println("Account balances are not within 10% of each other. Adjusting balances...")

		// Adjust balances to bring them within threshold
		err = adjustBalances(accounts, balances, config)
		if err != nil {
			log.Fatalf("Failed to adjust balances: %v", err)
		}

		// Re-fetch balances after adjustment
		balances, err = lib.GetBalances(accounts, config)
		if err != nil {
			log.Fatalf("Failed to get balances after adjustment: %v", err)
		}

		if lib.CheckBalancesWithinThreshold(balances, 0.10) {
			return
		}

		totalBalance := sdkmath.ZeroInt()
		for _, balance := range balances {
			totalBalance = totalBalance.Add(balance)
		}
		if totalBalance.IsZero() {
			fmt.Println("All accounts have zero balance. Proceeding without adjusting balances.")
			return
		}
		log.Fatalf("Account balances are still not within 10%% of each other after adjustment")
	}

	nodeURL := config.Nodes.RPC[0] // Use the first node

	chainID, err := lib.GetChainID(nodeURL)
	if err != nil {
		log.Fatalf("Failed to get chain ID: %v", err)
	}

	msgParams := config.MsgParams

	// Initialize gRPC client
	//	grpcClient, err := client.NewGRPCClient(config.Nodes.GRPC)
	//	if err != nil {
	//		log.Fatalf("Failed to create gRPC client: %v", err)
	//	}

	var wg sync.WaitGroup
	for _, account := range accounts {
		wg.Add(1)
		go func(acct types.Account) {
			defer wg.Done()

			// Get account info
			sequence, accNum, err := lib.GetAccountInfo(acct.Address, config)
			if err != nil {
				log.Printf("Failed to get account info for %s: %v", acct.Address, err)
				return
			}

			txParams := types.TransactionParams{
				Config:      config,
				NodeURL:     nodeURL,
				ChainID:     chainID,
				Sequence:    sequence,
				AccNum:      accNum,
				PrivKey:     acct.PrivKey,
				PubKey:      acct.PubKey,
				AcctAddress: acct.Address,
				MsgType:     config.MsgType,
				MsgParams:   msgParams,
			}

			// Broadcast transactions
			successfulTxns, failedTxns, responseCodes, _ := broadcast.Loop(txParams, BatchSize)

			fmt.Printf("Account %s: Successful transactions: %d, Failed transactions: %d\n", acct.Address, successfulTxns, failedTxns)
			fmt.Println("Response code breakdown:")
			for code, count := range responseCodes {
				percentage := float64(count) / float64(successfulTxns+failedTxns) * 100
				fmt.Printf("Code %d: %d (%.2f%%)\n", code, count, percentage)
			}
		}(account)
	}

	wg.Wait()
}

// adjustBalances transfers funds between accounts to balance their balances within the threshold
func adjustBalances(accounts []types.Account, balances map[string]sdkmath.Int, config types.Config) error {
	if len(accounts) == 0 {
		return errors.New("no accounts provided for balance adjustment")
	}

	// Calculate the total balance
	totalBalance := sdkmath.ZeroInt()
	for _, balance := range balances {
		totalBalance = totalBalance.Add(balance)
	}
	fmt.Printf("Total Balance across all accounts: %s %s\n", totalBalance.String(), config.Denom)

	if totalBalance.IsZero() {
		return errors.New("total balance is zero, nothing to adjust")
	}

	numAccounts := sdkmath.NewInt(int64(len(accounts)))
	averageBalance := totalBalance.Quo(numAccounts)
	fmt.Printf("Number of Accounts: %d, Average Balance per account: %s %s\n", numAccounts.Int64(), averageBalance.String(), config.Denom)

	// Define minimum transfer amount to avoid dust transfers
	minTransfer := sdkmath.NewInt(1000) // Adjust based on your token's decimal places
	fmt.Printf("Minimum Transfer Amount to avoid dust: %s %s\n", minTransfer.String(), config.Denom)

	// Create a slice to track balances that need to send or receive funds
	type balanceAdjustment struct {
		Account types.Account
		Amount  sdkmath.Int // Positive if needs to receive, negative if needs to send
	}
	var adjustments []balanceAdjustment

	threshold := averageBalance.MulRaw(10).QuoRaw(100) // threshold = averageBalance * 10 / 100
	fmt.Printf("Balance Threshold for adjustments (10%% of average balance): %s %s\n", threshold.String(), config.Denom)

	for _, acct := range accounts {
		currentBalance := balances[acct.Address]
		difference := averageBalance.Sub(currentBalance)

		fmt.Printf("Account %s - Current Balance: %s %s, Difference from average: %s %s\n",
			acct.Address, currentBalance.String(), config.Denom, difference.String(), config.Denom)

		// Only consider adjustments exceeding the threshold and minimum transfer amount
		if difference.Abs().GT(threshold) && difference.Abs().GT(minTransfer) {
			adjustments = append(adjustments, balanceAdjustment{
				Account: acct,
				Amount:  difference,
			})
			fmt.Printf("-> Account %s requires adjustment of %s %s\n", acct.Address, difference.String(), config.Denom)
		} else {
			fmt.Printf("-> Account %s is within balance threshold, no adjustment needed\n", acct.Address)
		}
	}

	// Separate adjustments into senders (negative amounts) and receivers (positive amounts)
	var senders, receivers []balanceAdjustment
	for _, adj := range adjustments {
		if adj.Amount.IsNegative() {
			// Check if the account has enough balance to send
			accountBalance := balances[adj.Account.Address]
			fmt.Printf("Sender Account %s - Balance: %s %s, Surplus: %s %s\n",
				adj.Account.Address, accountBalance.String(), config.Denom, adj.Amount.Abs().String(), config.Denom)

			if accountBalance.GT(sdkmath.ZeroInt()) {
				senders = append(senders, adj)
			} else {
				fmt.Printf("-> Account %s has zero balance, cannot send funds.\n", adj.Account.Address)
			}
		} else if adj.Amount.IsPositive() {
			fmt.Printf("Receiver Account %s - Needs: %s %s\n",
				adj.Account.Address, adj.Amount.String(), config.Denom)
			receivers = append(receivers, adj)
		}
	}

	// Perform transfers from senders to receivers
	for _, sender := range senders {
		// The total amount the sender needs to transfer (their surplus)
		amountToSend := sender.Amount.Abs()
		fmt.Printf("\nStarting transfers from Sender Account %s - Total Surplus to send: %s %s\n",
			sender.Account.Address, amountToSend.String(), config.Denom)

		// Iterate over the receivers who need funds
		for i := range receivers {
			receiver := &receivers[i]

			// Check if the receiver still needs funds
			if receiver.Amount.GT(sdkmath.ZeroInt()) {
				// Determine the amount to transfer:
				// It's the minimum of what the sender can send and what the receiver needs
				transferAmount := sdkmath.MinInt(amountToSend, receiver.Amount)

				fmt.Printf("Transferring %s %s from %s to %s\n",
					transferAmount.String(), config.Denom, sender.Account.Address, receiver.Account.Address)

				// Transfer funds from the sender to the receiver
				err := TransferFunds(sender.Account, receiver.Account.Address, transferAmount, config)
				if err != nil {
					return fmt.Errorf("failed to transfer funds from %s to %s: %v",
						sender.Account.Address, receiver.Account.Address, err)
				}

				fmt.Printf("-> Successfully transferred %s %s from %s to %s\n",
					transferAmount.String(), config.Denom, sender.Account.Address, receiver.Account.Address)

				// Update the sender's remaining amount to send
				amountToSend = amountToSend.Sub(transferAmount)
				fmt.Printf("Sender %s remaining surplus to send: %s %s\n",
					sender.Account.Address, amountToSend.String(), config.Denom)

				// Update the receiver's remaining amount to receive
				receiver.Amount = receiver.Amount.Sub(transferAmount)
				fmt.Printf("Receiver %s remaining amount needed: %s %s\n",
					receiver.Account.Address, receiver.Amount.String(), config.Denom)

				// If the sender has sent all their surplus, move to the next sender
				if amountToSend.IsZero() {
					fmt.Printf("Sender %s has sent all surplus funds.\n", sender.Account.Address)
					break
				}
			} else {
				fmt.Printf("Receiver %s no longer needs funds.\n", receiver.Account.Address)
			}
		}
	}

	fmt.Println("\nBalance adjustment complete.")
	return nil
}

func TransferFunds(sender types.Account, receiverAddress string, amount sdkmath.Int, config types.Config) error {
	// Add nil checks for keys
	if sender.PrivKey == nil {
		return fmt.Errorf("sender private key is nil")
	}
	if sender.PubKey == nil {
		return fmt.Errorf("sender public key is nil")
	}

	// Get the sender's account info
	sequence, accNum, err := lib.GetAccountInfo(sender.Address, config)
	if err != nil {
		return fmt.Errorf("failed to get account info for sender %s: %v", sender.Address, err)
	}

	nodeURL := config.Nodes.RPC[0]
	chainID, err := lib.GetChainID(nodeURL)
	if err != nil {
		return fmt.Errorf("failed to get chain ID: %v", err)
	}

	// Initialize gRPC client
	grpcClient, err := client.NewGRPCClient(config.Nodes.GRPC)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %v", err)
	}

	txParams := types.TransactionParams{
		Config:      config,
		NodeURL:     nodeURL,
		ChainID:     chainID,
		Sequence:    sequence,
		AccNum:      accNum,
		PrivKey:     sender.PrivKey,
		PubKey:      sender.PubKey,
		AcctAddress: sender.Address,
		MsgType:     "bank_send",
		MsgParams: types.MsgParams{
			FromAddress: sender.Address,
			ToAddress:   receiverAddress,
			Amount:      amount.Int64(),
			Denom:       config.Denom,
		},
	}

	fmt.Println("FROM TRANSFER, txParams config", txParams.Config)
	fmt.Println("FROM TRANSFER, txParams nodeURL", txParams.NodeURL)
	fmt.Println("FROM TRANSFER, txParams chainID", txParams.ChainID)
	fmt.Println("FROM TRANSFER, txParams sequence", txParams.Sequence)
	fmt.Println("FROM TRANSFER, txParams privKey", txParams.PrivKey.String())
	fmt.Println("FROM TRANSFER, txParams pubKey", txParams.PubKey.String())
	fmt.Println("FROM TRANSFER, txParams acctAddress", txParams.AcctAddress)
	fmt.Println("FROM TRANSFER, txParams accNum", txParams.AccNum)
	fmt.Println("FROM TRANSFER, txParams msgType", txParams.MsgType)
	fmt.Println("FROM TRANSFER, txParams msgParams", txParams.MsgParams)

	ctx := context.Background()
	resp, _, err := broadcast.SendTransactionViaGRPC(ctx, txParams, sequence, grpcClient)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %v", err)
	}

	if resp.Code != 0 {
		return fmt.Errorf("transaction failed with code %d: %s", resp.Code, resp.RawLog)
	}

	return nil
}
