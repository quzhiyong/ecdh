package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/quzhiyong/ecdh/ecdh"
	"github.com/quzhiyong/ecdh/ecdh_server"
)
func main() {
	pubKey1, privKey1:=ecdh_server.EcdhGetKey()
	pubKey2, privKey2:=ecdh_server.EcdhGetKey()
	ecdh_server.EcdhExchange(privKey1,pubKey2)
	ecdh_server.EcdhExchange(privKey2,pubKey1)
	//testECDH(ecdh.NewEllipticECDH(elliptic.P256()))
	//

}


func testECDH(e ecdh.ECDH, ) {
	var privKey1, privKey2 crypto.PrivateKey
	var pubKey1, pubKey2 crypto.PublicKey
	var pubKey1Buf, pubKey2Buf []byte
	var err error
	var ok bool
	var secret1, secret2 []byte

	privKey1, pubKey1, err = e.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
	}
	cs,_:=json.Marshal(pubKey1)
	fmt.Println("pubKey1",cs)



	privKey2, pubKey2, err = e.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
	}

	pubKey1Buf = e.Marshal(pubKey1)
	pubKey2Buf = e.Marshal(pubKey2)
	fmt.Println("pubKey1Buf:",hex.EncodeToString(pubKey1Buf))

	pubKey1, ok = e.Unmarshal(pubKey1Buf)
	if !ok {
		fmt.Println("Unmarshal does not work")
	}

	pubKey2, ok = e.Unmarshal(pubKey2Buf)
	if !ok {
		fmt.Println("Unmarshal does not work")
	}

	secret1, err = e.GenerateSharedSecret(privKey1, pubKey2)
	if err != nil {
		fmt.Println(err)
	}




	secret2, err = e.GenerateSharedSecret(privKey2, pubKey1)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("The two shared keys: %d, %d do not match", hex.EncodeToString(secret1), hex.EncodeToString(secret2))
	if !bytes.Equal(secret1, secret2) {
		fmt.Println("The two shared keys: %d, %d do not match", secret1, secret2)
	}


}
