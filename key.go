package go_token

type Key []byte

// 创建一个长度为128位（16字节）的密钥 传递的key大于16字节只截取有效位，位数不够填补空格 多退少补原则
func New_AESKey_128(key []byte) Key {
	l := len(key)
	if l < 16 {
		key = getSpace(key, 16-l)
	}
	return key[:16]
}

func New_AESKey_192(key []byte) Key {
	l := len(key)
	if l < 24 {
		key = getSpace(key, 24-l)
	}
	return key[:24]
}

func New_AESKey_256(key []byte) Key {
	l := len(key)
	if l < 32 {
		key = getSpace(key, 32-l)
	}
	return key[:32]
}

func New_DESKey_64(key []byte) Key {
	l := len(key)
	if l < 8 {
		key = getSpace(key, 8-l)
	}
	return key[:8]
}

func getSpace(buf []byte, n int) []byte {
	for i := 0; i < n; i++ {
		buf = append(buf, 32)
	}
	return buf
}
