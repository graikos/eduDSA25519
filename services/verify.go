package services

import (
	"ed/eddsa"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

type VerifyService interface {
	Verify(filepath string, pubkeyfilepath string, sigfilepath string) error
}

type verifyServiceImpl struct{}

func NewVerifyService() VerifyService {
	return &verifyServiceImpl{}
}

func (v *verifyServiceImpl) Verify(filepath, pubkeyfilepath, sigfilepath string) error {
	kf, err := os.Open(pubkeyfilepath)
	if err != nil {
		return fmt.Errorf("opening public key file: %v", err)
	}
	defer kf.Close()
	pemEncFile, err := io.ReadAll(kf)
	if err != nil {
		return fmt.Errorf("reading public key file: %v", err)
	}
	block, _ := pem.Decode(pemEncFile)
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("reading public key file: errror decoding PEM block")
	}

	pubkey, err := eddsa.PublicKeyFromBytes(block.Bytes)
	if err != nil {
		return err
	}

	sf, err := os.Open(sigfilepath)
	if err != nil {
		return fmt.Errorf("opening signature file: %v", err)
	}
	defer sf.Close()
	pemEncFile, err = io.ReadAll(sf)
	if err != nil {
		return fmt.Errorf("reading signature file: %v", err)
	}
	block, _ = pem.Decode(pemEncFile)
	if block == nil || block.Type != "SIGNATURE" {
		return fmt.Errorf("errror decoding PEM block")
	}

	f, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("opening input file: %v", err)
	}
	defer f.Close()

	input, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	return eddsa.Verify(block.Bytes, input, pubkey.Bytes())
}
