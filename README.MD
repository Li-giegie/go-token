## go-token 是一个用于web权限认证的包.帮助构建基于加密、验证用户身份，类似于jwt，但截然不同.

### 不是有流行的[JWT]()吗?为什么还要重复造轮子？对此我给出一下几点理由：
    在一些高性能的应用场景序列化、反序列化JSON会带来一笔不小的CPU开销。
    go-token不使用JSON序列化、反序列化已知类型的数据（除去interface、any），使用封包来避开JSON序列化、反序列化。
    加密方式自定义包含：Aes五中加密方式、Des加密方式、Rsa加密方式，如果有必要可以再扩充新的加密方式。
    删除一些JWT的属性字段，使用者根据需求给出需要的字段，减少不必要的开销
    不可否认JWT仍然是一个非常优秀的权限认证方案
### 原理
在go-token中一个token具有的属性：
    
    // 任意数据
    Data interface{}    //通常为用户的账号信息
    // 颁发者
    ID string				// token ID
    Issuer string			// 颁发者
    CreateAt int64			// 创建时间
    ActivationAt int64		// 活动时间
    ExpirationAt int64		// 结束时间
    method encdecryption.Method // 加密方法
加密任意数据+颁发者 --> 对加密数据取MD5值 --> 生成token实例 --> hexString作为token

go-token 会把任意数据和颁发者序列化成JSON和封装的bytes切片，按颁发者给出的method加密方法和秘钥key进行加密，加密完成后对加密取MD5值，防篡改。

[如何使用](./go-jwt_test.go)