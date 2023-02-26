package go_token

import "errors"

var (
	ModfToken_Error = errors.New("err: 当前token已被篡改 The current token is tampered with. Procedure")
	TokenExpirationTime_Error = errors.New("err :当前token已过期 token ExpirationTime")
	ModfAndTokenTokenExpirationTime_Error = errors.New("err :当前token过期和篡改 ModfToken_Error and token ExpirationTime")
)

