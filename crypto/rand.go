package crypto

import (
	"crypto/rand"
	"math/big"
)

// GenerateRandomInt generate a uniform random number given the range
func GenerateRandomInt(min int, max int) int {
	if min == max {
		return min
	}
	if min > max {
		// Swap if min > max to handle invalid input gracefully
		min, max = max, min
	}

	randomInt, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)+1))
	if err != nil {
		return min
	}
	return min + int(randomInt.Int64())
}
