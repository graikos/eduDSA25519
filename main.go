package main

import (
	"ed/services"
	"flag"
	"fmt"
	"os"
)

func main() {
	command := os.Args[1]

	switch command {
	case "sign":

		signCmd := flag.NewFlagSet("sign", flag.ExitOnError)
		keyFile := signCmd.String("key", "", "Specifies the private key file")
		inputFile := signCmd.String("input", "", "Specifies the input file to be signed")

		signCmd.Parse(os.Args[2:])
		fmt.Println(*keyFile, *inputFile)
		if *keyFile == "" || *inputFile == "" {
			fmt.Println("Not enough arguments provided.")
			os.Exit(1)
		}

		signer := services.NewSignService()
		err := signer.SignFile(*inputFile, *keyFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		os.Exit(0)

	case "verify":

		verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
		keyFile := verifyCmd.String("pubkey", "", "Specifies the public key file")
		inputFile := verifyCmd.String("input", "", "Specifies the input file")
		sigFile := verifyCmd.String("signature", "", "Specifies the signature file to be verified")

		verifyCmd.Parse(os.Args[2:])
		fmt.Println(*keyFile, *inputFile)
		if *keyFile == "" || *inputFile == "" || *sigFile == "" {
			fmt.Println("Not enough arguments provided.")
			os.Exit(1)
		}

		verifier := services.NewVerifyService()
		err := verifier.Verify(*inputFile, *keyFile, *sigFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("Signature is valid.")
		os.Exit(0)

	case "keygen":
		keygenService := services.NewKeyGenerationService()
		if err := keygenService.GenerateKeys(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}
