package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

func main() {
	filename := flag.String("file", "", "Path to the file")
	sign := flag.Bool("S", false, "If you want to sign the file")
	verify := flag.Bool("V", false, "If you want to verify the signature")
	publicPath := flag.String("key", "", "Name of the Public Key")

	flag.Parse()

	//fmt.Printf("Filename: '%s', Sign: %v, Verify: %v\n", *filename, *sign, *verify)

	if *filename == "" {
		fmt.Printf("\nYou must provide a file using the -file <file_localization>.\n")
		fmt.Println("And use -S (to sign) or -V (to verify) and -key <pub_key_localization>")
		os.Exit(1)
	}

	if *sign {
		file, err := os.Open(*filename)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			log.Fatal(err)
		}

		hash := hasher.Sum(nil)
		hashStr := hex.EncodeToString(hash)
		fmt.Printf("SHA-256 hash of %s: %s\n", *filename, hashStr)

		privateKey, publicKey, err := generateKeyPair("output-kopia.txt")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Public Key: %x\n", publicKey)

		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash)
		if err != nil {
			fmt.Printf("Error signing data: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Signature: %x\n", signature)

		err = os.WriteFile("signature.bin", signature, 0644)
		if err != nil {
			fmt.Printf("Error saving signature: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Signature saved to signature.bin")
	}

	if *verify {
		file, err := os.Open(*filename)
		if err != nil {
			fmt.Printf("Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		hasher := sha256.New()
		if _, err := io.Copy(hasher, file); err != nil {
			log.Fatal(err)
		}

		hash := hasher.Sum(nil)
		hashStr := hex.EncodeToString(hash)
		fmt.Printf("SHA-256 hash of %s: %s\n", *filename, hashStr)
		publicKey, err := loadPublicKey(*publicPath)
		if err != nil {
			log.Fatal(err)
		}

		signature, err := os.ReadFile("signature.bin")
		if err != nil {
			log.Fatal(err)
		}

		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash, signature)
		if err != nil {
			fmt.Printf("Signature verification failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("Signature verification succeeded")
	}
}

func generateKeyPair(fileName string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	numbers, err := os.Open(fileName)

	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := rsa.GenerateKey(numbers, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Save the private key to a PEM file
	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		return nil, nil, err
	}
	defer privateKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return nil, nil, err
	}
	fmt.Println("Private key saved to private_key.pem")

	// Marshal the public key to PKIX format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	// Save the public key to a PEM file
	publicKeyFile, err := os.Create("public_key.pem")
	if err != nil {
		return nil, nil, err
	}
	defer publicKeyFile.Close()

	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		return nil, nil, err
	}
	fmt.Println("Public key saved to public_key.pem")

	return privateKey, &privateKey.PublicKey, nil
}

func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	pubKeyPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pubKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unexpected type of public key")
	}
}
