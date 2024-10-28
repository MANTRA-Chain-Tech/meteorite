package broadcast

import (
	"fmt"
	"time"

	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	transfertypes "github.com/cosmos/ibc-go/v8/modules/apps/transfer/types"
	"github.com/somatic-labs/meteorite/lib"
	types "github.com/somatic-labs/meteorite/types"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

// Add these at the top of the file
type TimingMetrics struct {
	PrepStart  time.Time
	SignStart  time.Time
	BroadStart time.Time
	Complete   time.Time
	Position   int
}

func (t *TimingMetrics) LogTiming(sequence uint64, success bool, err error) {
	prepTime := t.SignStart.Sub(t.PrepStart)
	signTime := t.BroadStart.Sub(t.SignStart)
	broadcastTime := t.Complete.Sub(t.BroadStart)
	totalTime := t.Complete.Sub(t.PrepStart)

	status := "SUCCESS"
	if !success {
		status = "FAILED"
	}

	fmt.Printf("[POS-%d] %s Transaction %s: seq=%d prep=%v sign=%v broadcast=%v total=%v%s\n",
		t.Position,
		time.Now().Format("15:04:05.000"),
		status,
		sequence,
		prepTime,
		signTime,
		broadcastTime,
		totalTime,
		formatError(err))
}

func formatError(err error) string {
	if err != nil {
		return fmt.Sprintf(" error=\"%v\"", err)
	}
	return ""
}

var cdc = codec.NewProtoCodec(codectypes.NewInterfaceRegistry())

func init() {
	transfertypes.RegisterInterfaces(cdc.InterfaceRegistry())
	banktypes.RegisterInterfaces(cdc.InterfaceRegistry())
}

// Transaction broadcasts the transaction bytes to the given RPC endpoint.
func Transaction(txBytes []byte, rpcEndpoint string) (*coretypes.ResultBroadcastTx, error) {
	client, err := GetClient(rpcEndpoint)
	if err != nil {
		return nil, err
	}

	return client.Transaction(txBytes)
}

// broadcastLoop handles the main transaction broadcasting logic
func Loop(
	txParams types.TransactionParams,
	batchSize int,
	position int,
) (successfulTxns, failedTxns int, responseCodes map[uint32]int, updatedSequence uint64) {
	successfulTxns = 0
	failedTxns = 0
	responseCodes = make(map[uint32]int)
	sequence := txParams.Sequence

	for i := 0; i < batchSize; i++ {
		currentSequence := sequence

		metrics := &TimingMetrics{
			PrepStart: time.Now(),
			Position:  position,
		}

		// Prepare transaction
		metrics.SignStart = time.Now()

		// Start broadcast
		metrics.BroadStart = time.Now()
		resp, _, err := SendTransactionViaRPC(
			txParams,
			currentSequence,
		)
		metrics.Complete = time.Now()

		// Handle case where resp is nil but there's an error
		if err != nil {
			metrics.LogTiming(currentSequence, false, err)
			failedTxns++

			// Skip sequence number handling if resp is nil
			if resp == nil {
				continue
			}

			if resp.Code == 32 {
				// Extract the expected sequence number from the error message
				expectedSeq, parseErr := lib.ExtractExpectedSequence(err.Error())
				if parseErr != nil {
					fmt.Printf("[POS-%d] Failed to parse expected sequence: %v\n",
						position, parseErr)
					continue
				}

				sequence = expectedSeq
				fmt.Printf("[POS-%d] Set sequence to expected value %d due to mismatch\n",
					position, sequence)

				// Re-send the transaction with the correct sequence
				metrics = &TimingMetrics{
					PrepStart: time.Now(),
					Position:  position,
				}

				metrics.SignStart = time.Now()
				metrics.BroadStart = time.Now()
				resp, _, err = SendTransactionViaRPC(
					txParams,
					sequence,
				)
				metrics.Complete = time.Now()

				if err != nil {
					metrics.LogTiming(sequence, false, err)
					failedTxns++
					continue
				}

				metrics.LogTiming(sequence, true, nil)
				successfulTxns++
				responseCodes[resp.Code]++
				sequence++
				continue
			}
			continue
		}

		metrics.LogTiming(currentSequence, true, nil)
		successfulTxns++
		responseCodes[resp.Code]++
		sequence++
	}
	updatedSequence = sequence
	return successfulTxns, failedTxns, responseCodes, updatedSequence
}
