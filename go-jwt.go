package go_token

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	encdecryption "github.com/Li-giegie/go-encdecryption"
	"time"
)

const Len_65535 = int(^uint16(0))

var duration_30Min time.Duration

func init(){
	duration_30Min,_ = time.ParseDuration("30m")
}

type Issue struct {
	ID string				// token ID
	Issuer string			// 颁发者
	CreateAt int64			// 创建时间
	ActivationAt int64		// 活动时间
	ExpirationAt int64		// 结束时间
	method encdecryption.Method			// 加密方法
}

func (i *Issue) Marshal() ([]byte,error) {
	var buf = new(bytes.Buffer)
	var err error
	var tmpLen int

	tmpLen = len(i.ID)
	if tmpLen > Len_65535 {
		tmpLen = Len_65535
	}
	if err = binary.Write(buf,binary.LittleEndian,uint16(len(i.ID[:tmpLen]))); err != nil {
		return nil,err
	}
	if _,err = buf.WriteString(i.ID[:tmpLen]);err != nil {
		return nil,err
	}

	tmpLen = len(i.Issuer)
	if tmpLen > Len_65535 {
		tmpLen = Len_65535
	}
	if err = binary.Write(buf,binary.LittleEndian,uint16(len(i.Issuer[:tmpLen]))); err != nil {
		return nil,err
	}
	if _,err = buf.WriteString(i.Issuer[:tmpLen]);err != nil {
		return nil,err
	}

	if err = binary.Write(buf,binary.LittleEndian,uint64(i.CreateAt)); err != nil {
		return nil,err
	}
	if err = binary.Write(buf,binary.LittleEndian,uint64(i.ActivationAt)); err != nil {
		return nil,err
	}
	if err = binary.Write(buf,binary.LittleEndian,uint64(i.ExpirationAt)); err != nil {
		return nil,err
	}
	return buf.Bytes(),nil
}

func (i *Issue) Unmarshal(issue_bytes []byte)  {

	idLen := binary.LittleEndian.Uint16(issue_bytes[:2])
	idLen+=2
	i.ID = string(issue_bytes[2:idLen])

	issueLen := binary.LittleEndian.Uint16(issue_bytes[idLen:idLen+2])
	idLen+=2
	issueLen+=idLen
	i.Issuer = string(issue_bytes[idLen:issueLen])

	tmpLen := issueLen
	i.CreateAt = int64(binary.LittleEndian.Uint64(issue_bytes[tmpLen:tmpLen+8]))
	tmpLen+=8
	i.ActivationAt = int64(binary.LittleEndian.Uint64(issue_bytes[tmpLen:tmpLen+8]))
	tmpLen+=8
	i.ExpirationAt = int64(binary.LittleEndian.Uint64(issue_bytes[tmpLen:tmpLen+8]))
}

// 创建一个Token
type Token struct {
	Data interface{}
	Issue
}

// 新建一个默认的token：
// 其有效期为30分钟
// 加密算法为Aes CBC
// 颁发者为 当前主机的HostName
// key 密钥
func NewToken_Default(data interface{}) *Token  {

	var now = time.Now()
	return &Token{
		Data:  data,
		Issue: Issue{
			ID:           getID(),
			Issuer:       hostInfo.Hostname,
			CreateAt:     now.UnixNano(),
			ActivationAt: 0,
			ExpirationAt: now.Add(duration_30Min).UnixNano(),
			method: encdecryption.Method_AES_CBC,
		},
	}
}

func (t *Token) Marshal(key encdecryption.Key) (TokenInstance,error) {
	var buf = new(bytes.Buffer)

	by,err := t.Issue.Marshal()
	if err != nil { return nil, err }

	if err = binary.Write(buf,binary.LittleEndian,uint32(len(by))); err != nil{ return nil, err }

	if _,err = buf.Write(by); err != nil {
		return nil, err
	}

	by2,err2 := json.Marshal(t.Data)
	if err2 != nil { return nil, err2 }
	if _,err = buf.Write(by2); err != nil { return nil, err }

	var aesEncrypt []byte
	switch t.Issue.method {
	case encdecryption.Method_AES_CBC:
		aesEncrypt,err = encdecryption.AesEncryptCBC(buf.Bytes(),key)
	case encdecryption.Method_AES_CTR:
		aesEncrypt,err = encdecryption.AesCtrCrypt(buf.Bytes(),key)
	case encdecryption.Method_AES_CFB:
		aesEncrypt,err = encdecryption.AesEncryptCFB(buf.Bytes(),key)
	case encdecryption.Method_AES_ECB:
		aesEncrypt,err = encdecryption.AesEncryptECB(buf.Bytes(),key)
	case encdecryption.Method_AES_OFB:
		aesEncrypt,err = encdecryption.AesEncryptOFB(buf.Bytes(),key)
	case encdecryption.Method_DES:
		aesEncrypt,err = encdecryption.DesEncrypt(buf.Bytes(),key)
	case encdecryption.Method_RSA:
		aesEncrypt,err = encdecryption.RsaEncrypt(buf.Bytes(),key)
	default:
		return nil,errors.New("不存在的加密方式")
	}
	if err != nil {
		return nil, err
	}
	buf.Reset()
	// 写入加密后数据长度
	if err = binary.Write(buf,binary.LittleEndian,uint16(len(aesEncrypt)));err != nil {
		return nil, err
	}
	// 写入加密数据
	if _,err = buf.Write(aesEncrypt); err != nil {
		return nil, err
	}
	// 写入加密方法
	if err = buf.WriteByte(byte(t.method));err != nil{
		return nil, err
	}

	_md5 := GetMd5(buf.Bytes(),key)
	// 写入md5防篡改
	if _,err = buf.Write(_md5);err != nil {
		return nil, err
	}

	return buf.Bytes(),err
}

func (t *Token) Unmarshal(tokenBytes []byte,key encdecryption.Key) (error) {
	return  t.unmarshal(tokenBytes,key)
}

func (t *Token) UnmarshalHexString(hexString string,key encdecryption.Key) (error) {
	tokenBytes,err := hex.DecodeString(hexString)
	if err != nil {
		return err
	}
	return  t.unmarshal(tokenBytes,key)
}

func (t *Token) verifyMd5(tokenBytes []byte,key encdecryption.Key) ([]byte,error) {
	tl := binary.LittleEndian.Uint16(tokenBytes[:2])
	ok := bytes.Equal(GetMd5(tokenBytes[:tl+3],key),tokenBytes[tl+3:])
	if !ok {
		return tokenBytes[2:tl+3],ModfToken_Error
	}
	return tokenBytes[2:tl+3],nil
}

func (t *Token) unmarshal(tokenBytes []byte,key encdecryption.Key) error {
	var err error
	var tokenMod error
	tokenBytes,tokenMod = t.verifyMd5(tokenBytes,key)

	tlen := len(tokenBytes)-1
	t.method = encdecryption.Method(tokenBytes[tlen])

	var decode []byte
	switch t.Issue.method {
	case encdecryption.Method_AES_CBC:
		decode,err = encdecryption.AesDecryptCBC(tokenBytes[:tlen],key)
	case encdecryption.Method_AES_CTR:
		decode,err = encdecryption.AesCtrCrypt(tokenBytes[:tlen],key)
	case encdecryption.Method_AES_CFB:
		decode,err = encdecryption.AesDecryptCFB(tokenBytes[:tlen],key)
	case encdecryption.Method_AES_ECB:
		decode,err = encdecryption.AesDecryptECB(tokenBytes[:tlen],key)
	case encdecryption.Method_AES_OFB:
		decode,err = encdecryption.AesDecryptOFB(tokenBytes[:tlen],key)
	case encdecryption.Method_DES:
		decode,err = encdecryption.DesDecrypt(tokenBytes[:tlen],key)
	case encdecryption.Method_RSA:
		decode,err = encdecryption.RsaDecrypt(tokenBytes[:tlen],key)
	default:
		return errors.New("不存在的加密方式")
	}
	if err != nil {
		return err
	}

	issueLen := binary.LittleEndian.Uint32(decode[:4])
	t.Issue.Unmarshal(decode[4:4+issueLen])
	if err = json.Unmarshal(decode[4+issueLen:],&t.Data); err != nil {
		return err
	}
	t.ActivationAt = time.Now().UnixNano()

	if err =  t.verifyExpirationTime();err != nil {
		if tokenMod != nil {
			return ModfAndTokenTokenExpirationTime_Error
		}
		return err
	}
	return tokenMod
}

func (t *Token) verifyExpirationTime() error {
	if t.ActivationAt > t.ExpirationAt {
		return TokenExpirationTime_Error
	}
	return nil
}

type TokenInstance []byte

func (t *TokenInstance) Bytes() []byte {
	return *t
}

func (t *TokenInstance) HexString() string {
	return hex.EncodeToString(*t)
}