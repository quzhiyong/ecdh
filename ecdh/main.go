package ecdh

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"


	"encoding/hex"
	"fmt"

	"math/big"
)



func gmp_e(str string)string  {
	i,_:=new(big.Int).SetString(str,10)
	return  hex.EncodeToString(i.Bytes())
}

func gmpInit(s string) string  {
	b, _ := new(big.Int).SetString(s, 16)
	return b.String()
}
func main() {
	pubKey1, privKey1:=EcdhGetKey()
	pubKey2, privKey2:=EcdhGetKey()
	EcdhExchange(privKey1,pubKey2)
	EcdhExchange(privKey2,pubKey1)
	//testECDH(ecdh.NewEllipticECDH(elliptic.P256()))
	//

}

//EcdhExchange 交换秘钥
func EcdhExchange(privKey1 crypto.PrivateKey,pubKey2 crypto.PrivateKey)  {
	//创建一个P256ecdh
	e :=NewEllipticECDH(elliptic.P256())
	secret1, err := e.GenerateSharedSecret(privKey1, pubKey2)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("The two shared keys:", hex.EncodeToString(secret1))
}

//EcdhGetKey 获取一组ecdh Key数据
func EcdhGetKey()  (crypto.PrivateKey,crypto.PrivateKey){
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	var pubKeyBuf []byte
	var err error
	var ok bool
	//创建一个ecdh
	e :=NewEllipticECDH(elliptic.P256())
	privKey, pubKey, err = e.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
	}

	pubKeyBuf = e.Marshal(pubKey)

	fmt.Println("pubKeyBuf:",hex.EncodeToString(pubKeyBuf))


	pubKey, ok = e.Unmarshal(pubKeyBuf)
	if !ok {
		fmt.Println("Unmarshal does not work")
	}

	fmt.Println("privKey:",privKey)
	fmt.Println("pubKey:",pubKey)

	pubKey1Json, _ := json.Marshal(pubKey)
	fmt.Println("pubKey1Json:",string(pubKey1Json))

	return pubKey,privKey
}



func testECDH(e ECDH, ) {
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
