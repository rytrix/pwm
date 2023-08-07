package serialize

import (
	"bytes"
	"encoding/binary"
)

func SerializeMap(passwords *map[string][]byte) ([]byte, error) {
	var buffer bytes.Buffer
	for key, value := range(*passwords) {
		err := binary.Write(&buffer, binary.LittleEndian, uint64(len(key)))
		if err != nil {
			return nil, err
		}
		
		_, err = buffer.WriteString(key)
		if err != nil {
			return nil, err
		}

		err = binary.Write(&buffer, binary.LittleEndian, uint64(len(value)))
		if err != nil {
			return nil, err
		}

		_, err = buffer.Write(value)
		if err != nil {
			return nil, err
		}
	}

	return buffer.Bytes(), nil
}

func DeserializeMap(encodedBuffer []byte) (map[string][]byte, error) {
	newMap := make(map[string][]byte)

	buffer := bytes.NewReader(encodedBuffer)

	for buffer.Len() > 0 {
		var keyLen uint64
		err := binary.Read(buffer, binary.LittleEndian, &keyLen)
		if err != nil {
			return nil, err
		}

		key := make([]byte, keyLen)
		_, err = buffer.Read(key)
		if err != nil {
			return nil, err
		}

		var dataLen uint64
		err = binary.Read(buffer, binary.LittleEndian, &dataLen)
		if err != nil {
			return nil, err
		}

		data := make([]byte, dataLen)
		_, err = buffer.Read(data)
		if err != nil {
			return nil, err
		}

		newMap[string(key)] = data
	}

	return newMap, nil
}

