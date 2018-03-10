package main

import (
	"fmt"
  "crypto/elliptic"
  "crypto/rand"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"

)

// To encode publicKey use:
// publicKeyBytes, _ = x509.MarshalPKIXPublicKey(&private_key.PublicKey)

func main() {

	for i := 1; i < 21; i++ {
		p521 := elliptic.P521()
	  priv1, _ := ecdsa.GenerateKey(p521, rand.Reader)


		privateKeyBytes, _ := x509.MarshalECPrivateKey(priv1)
		publicKeyBytes, _ := x509.MarshalPKIXPublicKey(&priv1.PublicKey)

		encodedBytes := hex.EncodeToString(privateKeyBytes)
		encodedBytesPublic := hex.EncodeToString(publicKeyBytes)
		fmt.Printf("key Private %d: " + "%s\n", i, encodedBytes)
		fmt.Printf("key Public %d: " + "%s\n", i, encodedBytesPublic)

		privateKeyBytesRestored, _ := hex.DecodeString(encodedBytes)
		priv2, _ := x509.ParseECPrivateKey(privateKeyBytesRestored)

		data := []byte("data")
		// Signing by priv1
		r, s, _ := ecdsa.Sign(rand.Reader, priv1, data)


		// Verifying against priv2 (restored from priv1)
		if !ecdsa.Verify(&priv2.PublicKey, data, r, s) {
			fmt.Printf("Error\n")
			return
		}

		// fmt.Printf("Key was restored from string successfully\n")
	}


}
