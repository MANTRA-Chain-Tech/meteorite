package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	sdk "github.com/cosmos/cosmos-sdk/types"
	tx "github.com/cosmos/cosmos-sdk/types/tx"
)

type GRPCClient struct {
	conn     *grpc.ClientConn
	txClient tx.ServiceClient
}

func NewGRPCClient(grpcEndpoint string) (*GRPCClient, error) {
	// Create a custom certificate pool
	certPool := x509.NewCertPool()

	// Create TLS config with custom verification
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Temporarily set to true to fetch the cert
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Get the peer certificates
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no certificates found from peer")
			}

			// Add the server's certificate to our pool
			certPool.AddCert(cs.PeerCertificates[0])

			// Create a new chain verifier
			opts := x509.VerifyOptions{
				Roots:         certPool,
				CurrentTime:   time.Now(),
				DNSName:       cs.ServerName,
				Intermediates: x509.NewCertPool(),
			}

			// Add any intermediate certificates
			for _, cert := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}

			// Verify the certificate chain
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		},
	}

	// Create TLS credentials
	creds := credentials.NewTLS(tlsConfig)

	// Create connection with the TLS credentials
	conn, err := grpc.Dial(grpcEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}

	txClient := tx.NewServiceClient(conn)

	return &GRPCClient{
		conn:     conn,
		txClient: txClient,
	}, nil
}

func (c *GRPCClient) SendTx(ctx context.Context, txBytes []byte) (*sdk.TxResponse, error) {
	grpcRes, err := c.txClient.BroadcastTx(
		ctx,
		&tx.BroadcastTxRequest{
			Mode:    tx.BroadcastMode_BROADCAST_MODE_SYNC,
			TxBytes: txBytes,
		},
	)
	if err != nil {
		return nil, err
	}

	return grpcRes.TxResponse, nil
}

func (c *GRPCClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}
