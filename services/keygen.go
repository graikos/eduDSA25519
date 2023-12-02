package services

import (
	"ed/eddsa"
	"encoding/pem"
	"os"
)

type KeyGenerationService interface {
	GenerateKeys() error
}

type keyGenerationServiceImpl struct {
}

func NewKeyGenerationService() KeyGenerationService {
	return &keyGenerationServiceImpl{}
}

func (kg *keyGenerationServiceImpl) GenerateKeys() error {
	privf, err := os.OpenFile("priv.txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer privf.Close()

	privKey, pubKey := eddsa.GenerateKeys()
	privBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKey.Bytes(),
	}

	if err := pem.Encode(privf, privBlock); err != nil {
		return err
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKey.Bytes(),
	}

	pubf, err := os.OpenFile("pub.txt", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer pubf.Close()

	return pem.Encode(pubf, pubBlock)
}
