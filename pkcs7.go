package cryptopals

import "fmt"

func padPKCS7ToBlockSize(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length%blockSize == 0 {
		padding := make([]byte, blockSize)
		for i := 0; i < blockSize; i++ {
			padding[i] = byte(blockSize)
		}

		return append(data, padding...), nil
	}

	diff := blockSize - length%blockSize
	padding := make([]byte, diff)
	for i := 0; i < diff; i++ {
		padding[i] = byte(diff)
	}

	return append(data, padding...), nil
}

func unpadPKCS7(data []byte) ([]byte, error) {
	length := len(data)

	// Assume that the last byte was a padding byte
	paddingByte := data[length-1]
	count := byte(0)

	if paddingByte == 0 {
		return nil, fmt.Errorf("invalid zero padding byte: %d", paddingByte)
	}

	if paddingByte > 16 {
		return nil, fmt.Errorf("invalid padding byte: %d", paddingByte)
	}

	for i := length - 1; i >= 0; i-- {
		if data[i] == paddingByte {
			count++
			if count > paddingByte {
				return nil, fmt.Errorf("invalid padding byte: %d, count: %d", paddingByte, count)
			}
		} else {
			if count == paddingByte {
				return data[:i+1], nil
			}
			return nil, fmt.Errorf("invalid padding byte: %d, count: %d", paddingByte, count)
		}
	}

	return data, nil
}

func padPKCS7(plainTextStr string, length int) (string, error) {
	plainText := []byte(plainTextStr)

	if length > 256 {
		return "", fmt.Errorf("cannot pad length > 256")
	}

	if length == 0 {
		return plainTextStr, nil
	}

	textLength := len(plainText)
	diff := length - textLength

	if diff < 0 {
		return "", fmt.Errorf("plainText longer than length")
	}

	if diff == 0 {
		return plainTextStr, nil
	}

	padding := make([]byte, diff)
	for i := 0; i < diff; i++ {
		padding[i] = byte(diff)
	}

	return string(append(plainText, padding...)), nil
}
