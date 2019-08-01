package go_jwt

import (
	"fmt"
	"testing"
	"time"
)

func TestJwtClass_VerifyJwt(t *testing.T) {
	Jwt.VerifyJwt(
		"-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAn9i2WBjHUUcy7BrQXz3I\nHuZryHVZlTV+nraIz8FalSrByF9RWFKMFn3FJi53MP5JlMQp4u/m3QmNtZwOli8i\nKDjLf78X8tJX4Z2SmolNNYMq11lIfC90NQ+ZGebGU4GpvRTnO79cPGfmaKj1Q+GM\nd8SiFrSwwD8DHU7Idr8NWLlviAMsrwTs9d5w0Z58ty65Nc9pqRA6ZEIuuLzqTCR9\n1sf45dxPDL9j1d3slWnkLi8SU+V3DHSJvV3v8Ll7bHQiSwmQ90WUAVyE9i2RpSE+\nO1LNqnaRZPTF/OaYP45CiR0vODdogt1OeZYmhE2weDTwvjA8qAO/WiGRxO5l2Sf1\neIuxFpnHon1e+DN0Qg6wD5+npnttnO9ORaSW56cJFFDf5pePd5jIMLOHzmbT39a6\nWn0l4DzsISU4/2sfAyu8PZu8lQ572C+RF8UXaQ3ip7V5RlgB2drxzPDOnMCrjwR7\nWMTzCAz/SIBa0ONKDy35RLYmXHinTu1iHOAX/cvmJq24Uq/LrjHT+hkbEPVkz0cC\nMNhzHyPh0pPBJH+EXu9GQanWK9eCZb+2o9DD4cjub5V52xAgAHJIQrg8Ml7JYNx1\nhQRUkQacQXK71tmXiKbEq8v3xQcYy6ggd2DXDiyTV/N4lbZ3ttBxjR0J719UkvsF\nqdKAUt15Zs4vb0/viEF5nScCAwEAAQ==\n-----END PUBLIC KEY-----",
		`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTE5ODU3NjQsImlhdCI6MTU1MTk2NDE2NCwicGF5bG9hZCI6bnVsbH0.maQFKzl8R2ECfvXvEumOC-ofFVkTKu95ZvNURuZ6-K3CHAvxHEyeWjRsYZI2qD0XQbI0RTCMjpED8pd1vRnzRZWhFmaG0lZJYzwtlD6hjWfyNj1vGfoTYGPGFY7IaI4sWyq07RRWneq9C6B4CgniT5CFlKsktQm4kmzZGuStnpqJnA23prDmNCuVy4uAAdnKvABjVGBLtwB08eU_jmc2Nks3hW1NtPsOmyb4MCjRdqDDfRIz3VUYWPCCKK2AFdCZylfft9G2cQ3p92byH-143IRqwOlqA8k5CMh9d_UX8TmL3qaRaqlaXhFtB0y761XPuQpMSJNQC4A_wF-xABbYgW5E4QekZ4lXft3SIa_mPVgmRI8xbCXCzoz7snsdcZ5549mZNF02AqcDdhbS0IU6cb56AuefHtgU6K_DTNnsvNLUUv2y_a7JnvkrXd9iWOaaZa9vOdLn61eAIUIKc4uW0r2YszXu-VyCnvEVqvo0wnf6V4YTwd6r4WpS7zsK1jGZvZx_BN9CKr4CKXiKpFIH8k6ENgc0qvTDDd1xdqIlAFlKQ5LkU9UwqWZ-WTqXv4RySBWGeeBPfwrKuseqmAU9uIUOx2bjHeiQMrct6lleA6sQ2QJhg3Szo5Z9OqVtUAouhiL9y0wrJJaVnk4og11VALClrmsnnEes-3FeMcQXvaU`)
}

func TestJwtClass_GetJwt(t *testing.T) {
	a := Jwt.GetJwt("-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----",
6 * time.Hour, nil)
	fmt.Println(a)
}
