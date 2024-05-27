package services

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/shamir"
	httpclient "github.com/mdshahjahanmiah/gateway-service/pkg/client"
	"github.com/pkg/errors"
	"net/http"
	"sync"
	"time"
)

// DecryptRequest represents the request payload for decryption
type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

// PartialDecryptRequest represents the payload sent to the decryption service for partial decryption
type PartialDecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
	Share      string `json:"share"`
}

// DecryptResponse represents the response from the decryption service
type DecryptResponse struct {
	DecryptedMessage string `json:"decrypted_message"`
}

// PartialDecryptResponse represents the response from a partial decryption
type PartialDecryptResponse struct {
	PartialDecryption string `json:"partial_decryption"`
}

// DsService defines the interface for the decryption service
type DsService interface {
	Decrypt(ciphertext string) (string, error)
}

// dsService implements the DsService interface
type dsService struct {
	client     *httpclient.Client
	decryptURL string
	keyShares  []KeyShareResponse
}

// NewDsService creates a new DsService with the specified decryption service URL and timeout
func NewDsService(decryptURL string, timeout time.Duration, keyShares []KeyShareResponse) DsService {
	client := httpclient.NewHttpClient(timeout)
	return &dsService{
		client:     client,
		decryptURL: decryptURL,
		keyShares:  keyShares,
	}
}

// Decrypt performs the decryption using partial decryptions from key shares
func (ds *dsService) Decrypt(ciphertext string) (string, error) {
	partialDecryptions := make([]string, len(ds.keyShares))

	var wg sync.WaitGroup
	var mu sync.Mutex
	errChan := make(chan error, len(ds.keyShares))

	for i, share := range ds.keyShares {
		wg.Add(1)
		go func(i int, share KeyShareResponse) {
			defer wg.Done()
			partialReq := PartialDecryptRequest{
				Ciphertext: ciphertext,
				Share:      share.Share,
			}

			partialDecryptResp, err := ds.sendPartialDecryptRequest(partialReq)
			if err != nil {
				errChan <- err
				return
			}

			mu.Lock()
			partialDecryptions[i] = partialDecryptResp.PartialDecryption
			mu.Unlock()
		}(i, share)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return "", err
	}

	// Combine partial decryptions to get the final decrypted message
	finalDecryption, err := ds.combinePartialDecryptions(partialDecryptions)
	if err != nil {
		return "", err
	}

	return finalDecryption, nil
}

// sendPartialDecryptRequest sends a partial decryption request to the decryption service
func (d *dsService) sendPartialDecryptRequest(req PartialDecryptRequest) (*PartialDecryptResponse, error) {

	fmt.Println("Decrypting partial: ", req)

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	resp, err := d.client.Post(d.decryptURL+"/partial-decrypt", "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get partial decryption")
	}

	var partialDecryptResp PartialDecryptResponse
	if err := json.NewDecoder(resp.Body).Decode(&partialDecryptResp); err != nil {
		return nil, err
	}

	return &partialDecryptResp, nil
}

// combinePartialDecryptions combines partial decryptions to get the final decrypted message
func (ds *dsService) combinePartialDecryptions(partials []string) (string, error) {
	// Decode base64-encoded shares
	shares := make([][]byte, len(partials))
	for i, partial := range partials {
		decoded, err := base64.StdEncoding.DecodeString(partial)
		if err != nil {
			return "", err
		}
		shares[i] = decoded
	}

	// Combine shares using Shamir's Secret Sharing
	secret, err := shamir.Combine(shares)
	if err != nil {
		return "", err
	}

	return string(secret), nil
}
