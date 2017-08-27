// A credit card number is composed by a six-digit Issuer Identification Number (IIN),
// a variable length (7-12) individual account identifier and a single check digit.
package helper

import (
	"crypto/cipher"
	"crypto-fpe/fpe"
)

const(
	// The radix to cipher Credit Cards (i.e. decimal numbers) is 10
	CCRadix = 10
	// A CC length is between 13 and 19 digits
	ccMinLen = 13
	ccMaxLen = 19
)

type FpeCreditCard interface {
	// Crypt encrypts or decrypts a credit card number.
	Crypt(src string) (string, error)
}

type fpeWithSetTweak interface {
	cipher.BlockMode
	SetTweak([]byte)
}

type ccFpe struct {
	m	cipher.BlockMode
}

func newFPECreditCard(m cipher.BlockMode) *ccFpe {
	return &ccFpe{
		m:	m,
	}
}

type fpeCreditCardProcessor ccFpe

func NewFPECreditCardProcessor(m cipher.BlockMode) FpeCreditCard {
	return (*fpeCreditCardProcessor)(newFPECreditCard(m))
}

func (x *fpeCreditCardProcessor) Crypt(in string) (string, error) {
	var runes = []rune(in)
	var numeralString = make([]uint16, ccMaxLen)
	var numStrIdx = 0

	// Create numeral string
	for _, r := range runes {
		// We only take digits and leave eventual separators char like '-', ' '
		if r >= 48 && r <= 57 {
			numeralString[numStrIdx] = uint16(r) - 48
			numStrIdx++
		}
	}

	// We remove unused trailing digits (needed because CC length is not fix) and the checksum
	numeralString = numeralString[:numStrIdx-1]

	// Encrypt numeral string
	var b = fpe.NumeralStringToBytes(numeralString)
	x.m.CryptBlocks(b, b)
	numeralString = fpe.BytesToNumeralString(b)

	// Compute ciphertext Luhn checksum
	numeralString = append(numeralString, luhnChecksum(numeralString))

	numStrIdx = 0
	// Copy enciphered data back to runes
	for i, r := range runes {
		// We replace clear text digits with enciphered ones, while preserving eventual separators
		// char like '-', ' '
		if r >= 48 && r <= 57 {
			runes[i] = rune(numeralString[numStrIdx] + 48)
			numStrIdx++
		}
	}

	return string(runes), nil
}

func (x *fpeCreditCardProcessor) SetTweak(tweak []byte) {
	var fpeModeWithSetTweak, ok = x.m.(fpeWithSetTweak)
	if !ok {
		panic("fpeCreditCardProcessor/SetTweak: BlockMode must have a SetTweak function.")
	}
	fpeModeWithSetTweak.SetTweak(tweak)
}

// We compute the Luhn Checksum over the numeral string.
func luhnChecksum(numeralString []uint16) (uint16) {
	var luhnArray = []uint16{0, 2, 4, 6, 8, 1, 3, 5, 7, 9}
	var l = len(numeralString)
	var checksum = uint16(0)

	for i := 0; i < l; i++ {
		if i%2 == 0 {
			checksum += luhnArray[numeralString[l-i-1]]
		} else {
			checksum += numeralString[l-i-1]
		}
	}
	checksum = (10 - (checksum % 10)) %10
	return checksum
}

func validateChecksum(numeralString []uint16) (bool) {
	var creditCardNbr = numeralString[:len(numeralString)-1]
	var checksum = numeralString[len(numeralString)-1]
	var computedChecksum = luhnChecksum(creditCardNbr)

	if computedChecksum == checksum {
		return true
	} else {
		return false
	}
}