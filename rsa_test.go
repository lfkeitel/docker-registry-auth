package dockerauth

import "testing"

const privKeyID = "W72W:52MO:BCLR:UKQI:I6AY:WYSP:YYVA:HXLY:RJ5P:462D:AI4Q:JQFB"

func TestRSAFingerprint(t *testing.T) {
	config = &Config{
		Registry: &RegistryConfig{},
	}
	config.Registry.Auth.Key = "testdata/auth.key"

	key, err := getPrivateKey()
	ok(t, err)

	id := getRSAKeyID(key)
	if id != privKeyID {
		t.Errorf("Incorrect key ID. Expected %s, got %s", privKeyID, id)
	}
	equals(t, id, privKeyID)
}
