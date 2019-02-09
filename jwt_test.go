package p_jwt

import (
	"testing"
)

func TestJwtClass_VerifyJwt(t *testing.T) {
	Jwt.VerifyJwt(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo8NP+SYklqU1kTHrCRVQ
o2VI9jg3pxbCG6wXdmpoSwt30TeIWYUnBhDDZ22eLWADYPci5HwIRw6kphadDHB/
K0cE79QWpo9hOo8/3hXCr0Tfs2MG5xlolqTn/svdf/tBtUypxe828mKU+YuNavX+
8F60Yunq8ZRoaRlO3T+O0App4A6at5umG7qncZdL/GOzyyw8K+cYVkXN6DSOUs7T
cigFMKywMuW1wh0SCDZjmebUGO+S4KKw1oEnzP6zO6RQqTfJVGsQnNJkczQ8vUQ/
8l8Y2WohU/zmCsPgr/suSdyHWMv0KEoDjB0hCbhx3Aqy1GpYw/6gj1M949JN10Ti
0wIDAQAB
-----END PUBLIC KEY-----`, `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDc3NTA1NjAsImlhdCI6MTU0NzcyODk2MCwicGF5bG9hZCI6eyJ1c2VyX2lkIjoyfX0.SSPoUOaFybH2jqzdBkDn5Iiimx806VDut4JpeqpxcJa8JqYTrctBTgymaofwxfy4zSHV6lqZEwPoTmsTH9GljEJf_xIJQR3WleT7GuGSABn8QFxQlUo9-J8I8D9isPJMgfZa8AlZsfG7Y-M7JZO2q-M2fWCwGiZ3XSpEDlHmJ3X-sOQSG28dAYpVXSXDXoIl7-7WIrdo6zSdp3575Q1y3qZflTj-8hdoniYgOzkxw11D-WkRDGnweSIClzdAmMiYiOrjSjVyJZVav2Wnv0z9twrK8mx3iWudqA3FZ3SZ4sksGNJFKDQtLGbPtWJUPjI2B5JWZMhW5RWGVWnkrB4L2Q`)
}
