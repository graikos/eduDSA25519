package services

import (
	"ed/eddsa"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type SignService interface {
	SignFile(filepath string, key *eddsa.PrivateKey) error
	SignBytes(msg []byte, key *eddsa.PrivateKey) ([]byte, error)
}

type signServiceImpl struct{}

func NewSignService() SignService {
	return &signServiceImpl{}
}

// SignBytes signs a message and returns the signature in bytes
func (s *signServiceImpl) SignBytes(msg []byte, privKey *eddsa.PrivateKey) ([]byte, error) {
	sig, err := eddsa.Sign(privKey, msg)
	if err != nil {
		return nil, fmt.Errorf("signing input file: %v", err)
	}
	return sig, nil
}

// SignFile signs a file and outputs the signature in a PEM encoded file
func (s *signServiceImpl) SignFile(filepath string, privKey *eddsa.PrivateKey) error {
	f, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("opening input file: %v", err)
	}
	defer f.Close()

	input, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("reading input file: %v", err)
	}

	sig, err := eddsa.Sign(privKey, input)
	if err != nil {
		return fmt.Errorf("signing input file: %v", err)
	}

	sf, err := os.OpenFile("sig.pem", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer sf.Close()

	sigBlock := &pem.Block{
		Type:  "SIGNATURE",
		Bytes: sig,
	}

	return pem.Encode(sf, sigBlock)
}
