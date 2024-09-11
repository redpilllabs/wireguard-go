package crypto

import (
	"crypto/rand"
	"math/big"
)

// GenerateRandomInt generate a uniform random number given the range
func GenerateRandomInt(min int, max int) int {
	if max == 0 {
		return 0
	}
	if min == max {
		return min
	}
	randomInt, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)+1))
	if err != nil {
		return 0
	}
	return min + int(randomInt.Int64())
}
