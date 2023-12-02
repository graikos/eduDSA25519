package services

import (
	"ed/eddsa"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type SignService interface {
	SignFile(filepath string, keypath string) error
}

type signServiceImpl struct{}

func NewSignService() SignService {
	return &signServiceImpl{}
}

func (s *signServiceImpl) SignFile(filepath, keypathstring string) error {

	kf, err := os.Open(keypathstring)
	if err != nil {
		return fmt.Errorf("opening private key file: %v", err)
	}
	defer kf.Close()
	pemEncFile, err := io.ReadAll(kf)
	if err != nil {
		return fmt.Errorf("reading private key file: %v", err)
	}

	block, _ := pem.Decode(pemEncFile)
	if block == nil || block.Type != "PRIVATE KEY" {
		return fmt.Errorf("errror decoding PEM block")
	}

	f, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("opening input file: %v", err)
	}
	defer f.Close()

	privKey := eddsa.PrivateKeyFromBytes(block.Bytes)

	input, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("reading input file: %v", err)
	}

	sig, err := eddsa.Sign(privKey, input)
	if err != nil {
		return fmt.Errorf("signing input file: %v", err)
	}

	sf, err := os.OpenFile("sig.txt", os.O_CREATE|os.O_WRONLY, 0644)
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
