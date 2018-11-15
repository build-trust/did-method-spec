// This code illustrates the process of generating a unique `idstring`

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"

	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multihash"
	"github.com/ockam-network/did"
)

func main() {
	// generate keypair
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	h := hex.EncodeToString(publicKey)
	fmt.Printf("%64s - %6s - public key\n", h, "hex")

	// hash the public key
	hash := sha3.Sum256(publicKey)
	buf := hash[:]
	h = hex.EncodeToString(buf)
	fmt.Printf("%64s - %6s - sha3-256 hash of public key\n", h, "hex")

	// truncate the hash to the lower 20 bytes
	buf = hash[len(buf)-20:]
	h = hex.EncodeToString(buf)
	fmt.Printf("%64s - %6s - sha3-256 hash of public key (lower 20 bytes / 160 bits)\n", h, "hex")

	// prepend the multihash label for the hash algo, skip the varint length of the multihash, since that is fixed to 20
	buf = append([]byte{multihash.SHA3_256}, buf...)
	h = hex.EncodeToString(buf)
	fmt.Printf("%64s - %6s - multi hash prefix for sha3-256 (0x16) + hash of public key (lower 20 bytes)\n", h, "hex")

	// base58 encode the above value
	id := base58.Encode(buf)
	fmt.Printf("%64s - %6s - multi hash prefix for sha3-256 (0x16) + hash of public key (lower 20 bytes)\n", id, "base58")

	// make the ockam DID
	d := &did.DID{Method: "ockam", ID: id}
	fmt.Println(d)

	// Example Output: did:ockam:2PCd14L1pLMpfSfpgKe2HyYZFu2pf
}
