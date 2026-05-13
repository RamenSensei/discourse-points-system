package auth

import (
	"encoding/base64"
	"encoding/hex"
)

// helpers used by tests
func base64StdEncode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func hexMAC(key, msg []byte) string   { return hex.EncodeToString(mac(key, msg)) }
