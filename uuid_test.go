package dockerauth

import (
	"regexp"
	"testing"
)

var uuidRegex = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`)

func TestUUID(t *testing.T) {
	uuid1, err := generateUUID()
	ok(t, err)
	uuid2, err := generateUUID()
	ok(t, err)

	assert(t, uuid1 != uuid2, "Duplicated UUIDS: %s, %s", uuid1, uuid2)
	assert(t, uuidRegex.MatchString(uuid1), "Incorrect UUID format: %s", uuid1)
	assert(t, uuidRegex.MatchString(uuid2), "Incorrect UUID format: %s", uuid2)
}
