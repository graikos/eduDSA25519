package services

import (
	"ed/eddsa"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type KeyReaderService interface {
	ReadPrivatekey(string) (*eddsa.PrivateKey, error)
}

type keyReaderServiceImpl struct{}

func NewKeyReaderService() KeyReaderService {
	return &keyReaderServiceImpl{}
}

// ReadPrivateKey reads a PEM encoded private key file and returns a private key object
func (kr *keyReaderServiceImpl) ReadPrivatekey(keypath string) (*eddsa.PrivateKey, error) {
	kf, err := os.Open(keypath)
	if err != nil {
		return nil, fmt.Errorf("opening private key file: %v", err)
	}
	defer kf.Close()
	pemEncFile, err := io.ReadAll(kf)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %v", err)
	}

	block, _ := pem.Decode(pemEncFile)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("errror decoding PEM block")
	}

	return eddsa.PrivateKeyFromBytes(block.Bytes), nil
}
