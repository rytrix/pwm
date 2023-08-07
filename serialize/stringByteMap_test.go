package serialize_test

import (
	"pwm/serialize"
	"testing"
)

func areMapsEqual(map1, map2 map[string][]byte) bool {
	if len(map1) != len(map1) {
		return false
	}

	for key, value := range(map1) {
		value2, ok := map2[key]
		if !ok {
			return false
		}

		for i := 0; i < len(value); i++ {
			if value[i] != value2[i] {
				return false
			}
		}
	}

	return true
}

func TestMap(t *testing.T) {
	passwords := make(map[string][]byte)

	password := []byte("testing")
	passwords["idk"] = password 

	encoded, err := serialize.SerializeMap(&passwords)
	if err != nil {
		t.Error(err)
	}

	newMap, err := serialize.DeserializeMap(encoded)
	if err != nil {
		t.Error(err)
	}

	if !areMapsEqual(passwords, newMap) {
		t.Error("maps not equal")
	}
}
