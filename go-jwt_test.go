package go_token

import (
	"encoding/base64"
	"fmt"
	encdecryption "github.com/Li-giegie/go-encdecryption"
	"testing"
	"time"
)

func TestNewToken_Default(t *testing.T) {
	token := NewToken_Default("hello i'm lisa")
	token.ExpirationAt=time.Now().Add(time.Second).UnixNano()
	key := encdecryption.New_AESKey_128([]byte("key==//-"))
	ins,err := token.Marshal(key)
	fmt.Println("token: ",ins.HexString())
	var token2 Token
	//ins=append(ins.Bytes(), 1)
	err = token2.Unmarshal(ins.Bytes(),key)
	fmt.Println("序列化：",err,token2)

	for i:=0;i<5;i++ {
		err = token2.Unmarshal(ins.Bytes(),key)
		fmt.Println(i,err,token2)
		time.Sleep(time.Second)
		if i == 3 {
			ins= append(ins, 1)
		}
	}
}

func TestGetMd5(t *testing.T) {
	//fmt.Println(GetMd5([]byte("asdasd")),nil)
	fmt.Println(base64.URLEncoding)
}
