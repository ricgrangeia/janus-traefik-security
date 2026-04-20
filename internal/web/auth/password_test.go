package auth

import "testing"

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !VerifyPassword("correct-horse-battery-staple", h) {
		t.Fatal("verify should succeed for correct password")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("verify must fail for wrong password")
	}
	if VerifyPassword("", h) {
		t.Fatal("empty password must not verify")
	}
}

func TestHashProducesDifferentSalts(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("hashes must differ across invocations (random salt)")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	cases := []string{"", "not-a-hash", "$argon2id$v=19$bad", "$argon2i$v=19$m=1,t=1,p=1$YWJj$YWJj"}
	for _, c := range cases {
		if VerifyPassword("x", c) {
			t.Errorf("expected reject: %q", c)
		}
	}
}
