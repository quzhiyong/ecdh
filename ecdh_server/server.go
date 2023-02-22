package ecdh_server

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/quzhiyong/ecdh/ecdh"

	"encoding/hex"
	"fmt"

	"math/big"
)



func Gmp_e(str string)string  {
	i,_:=new(big.Int).SetString(str,10)
	return  hex.EncodeToString(i.Bytes())
}
func GmpbigIntToHex(i *big.Int) string  {

	return  hex.EncodeToString(i.Bytes())
}
func GmpHexTobigInt(s string) *big.Int  {
	b, _ := new(big.Int).SetString(s, 16)
	return b
}
func GmpInit(s string) string  {
	b, _ := new(big.Int).SetString(s, 16)
	return b.String()
}

//EcdhExchange 交换秘钥
func EcdhExchange(privKey1 crypto.PrivateKey,pubKey2 crypto.PrivateKey)  (string,string){
	//创建一个P256ecdh
	e :=ecdh.NewEllipticECDH(elliptic.P256())
	x,y, err := e.GenerateSharedSecret(privKey1, pubKey2)
	if err != nil {
		fmt.Println(err)
	}
	return  hex.EncodeToString(x), hex.EncodeToString(y)
}

//EcdhGetKey 获取一组ecdh Key数据
func EcdhGetKey()  (crypto.PrivateKey,crypto.PrivateKey){
	var privKey crypto.PrivateKey
	var pubKey crypto.PublicKey
	var pubKeyBuf []byte
	var err error
	var ok bool
	//创建一个ecdh
	e :=ecdh.NewEllipticECDH(elliptic.P256())
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

	x1,y1, err := e.GenerateSharedSecret(privKey1, pubKey2)
	if err != nil {
		fmt.Println(err)
	}




	x2,y2, err := e.GenerateSharedSecret(privKey2, pubKey1)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("The two shared keys: %d, %d do not match", hex.EncodeToString(x1), hex.EncodeToString(y1))
	if !bytes.Equal(secret1, secret2) {
		fmt.Println("The two shared keys: %d, %d do not match", x2, y2)
	}


}
