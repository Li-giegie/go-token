package go_token

import (
	"fmt"
	"testing"
	"time"
)

func TestNewToken_Default(t *testing.T) {
	// 创建一个默认Token
	token := NewToken_Default("hello i'm lisa")
	// 修改过期时间 默认为30分钟
	token.ExpirationAt=time.Now().Add(time.Second*2).UnixNano()
	// 底层数据类型为[]byte 创建一个长度为128位（16字节）的密钥 传递的key大于16字节只截取有效位，位数不够填补空格 多退少补原则
	key := New_AESKey_128([]byte("key==//-"))
	// 序列化token 返回token实例和错误
	ins,err := token.Marshal(key)
	// 打印token实例字符串
	fmt.Println("token: ",ins.HexString())

	//创建一个用于反序列化的token
	var token2 Token

	// 反序列化5次 间隔1秒钟，反序列化第二次token过期err返回错误
	// 入参可以是token实例的bytes
	for i:=0;i<5;i++ {
		err = token2.Unmarshal(ins.Bytes(),key)
		// 用法2 常用
		//err = token2.UnmarshalHexString(ins.HexString(),key)
		fmt.Println(i,err,token2)
		time.Sleep(time.Second)

	}
}
