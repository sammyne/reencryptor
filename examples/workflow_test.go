package examples_test

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/sammyne/reencryptor/proxy"

	"github.com/sammyne/reencryptor/recipient"

	"github.com/sammyne/reencryptor"

	"github.com/sammyne/reencryptor/sender"
)

func ExampleWorkflow() {
	msg, err := reencryptor.NewEncryptableMessage(rand.Reader)
	if err != nil {
		fmt.Println("failed to generate an encryptable message:", err)
		return
	}

	curve := reencryptor.NewBN256()

	// Alice as sender
	Alice, err := sender.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println("failed to generate a key for the sender:", err)
		return
	}

	// Alice do the 1st-level encryption and hand over the (ciphertext, tag) to proxy
	ciphertext, tag, err := sender.Encrypt(msg, &Alice.PublicKey)
	if err != nil {
		fmt.Println("failed to encrypt message:", err)
		return
	}

	// Bob generate his key
	Bob, err := recipient.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println("failed to generate a key for the recipient:", err)
		return
	}

	// Alice fetch Bob's public key and generate key for re-encryption in proxy
	reEncryptionKey := sender.DeriveReEncryptionKey(&Bob.PublicKey, Alice)

	// Proxy re-encrypt the tag with the re-rencryption key from Alice
	reEncryptedTag, err := proxy.ReEncrypt(tag, reEncryptionKey)
	if err != nil {
		fmt.Println("failed to re-encrypt tag:", err)
		return
	}

	// Bob download (ciphertext, reEncryptedTag) from proxy, and decrypt with its own private key
	recovered, err := recipient.ReDecrypt(ciphertext, reEncryptedTag, Bob)
	if err != nil {
		fmt.Println("failed decrypt ciphertext:", err)
		return
	}

	// then the msg should be decrypted successfully
	fmt.Println(bytes.Equal(msg, recovered))

	// Output:
	// true
}
