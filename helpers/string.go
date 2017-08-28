package helper

import (
	"crypto-fpe/fpe"
	"fmt"
	"bytes"
	"crypto/cipher"
)

type FpeString interface {
	// Crypt encrypts or decrypts a string.
	Crypt(in string) (string, error)
	SetTweak(tweak []byte)
}

type strFpe struct {
	m	          cipher.BlockMode
	alphabetMap   map[rune]uint16
	alphabetSlice []rune
}

func newFPEString(m cipher.BlockMode, alphabet string) *strFpe {
	var alphabetSize = len(alphabet)
	var alphabetMap = make(map[rune]uint16)
	var alphabetSlice = make([]rune, alphabetSize)

	SetAlphabet(alphabetMap, alphabetSlice, alphabet)

	return &strFpe{
		m:         		m,
		alphabetMap:	alphabetMap,
		alphabetSlice: 	alphabetSlice,
	}
}

type fpeStringProcessor strFpe

func NewFpeStringProcessor(m cipher.BlockMode, alphabet string) FpeString {
	return (*fpeStringProcessor)(newFPEString(m, alphabet))
}


func (x *fpeStringProcessor) Crypt(in string) (string, error) {
	var numeralString, err = toNumeralString(x.alphabetMap, in)
	if err != nil {
		return "", err
	}

	var b = fpe.NumeralStringToBytes(numeralString)
	x.m.CryptBlocks(b, b)
	numeralString = fpe.BytesToNumeralString(b)

	return fromNumeralString(x.alphabetSlice, numeralString)
}

func SetAlphabet(dstMap map[rune]uint16, dstSlice []rune, alphabet string) (error){
	for i, c := range alphabet {
		dstSlice[i] = c
		_, duplicateKey := dstMap[c]
		if duplicateKey {
			return fmt.Errorf("Duplicate character %q at index %d", c, i)
		}
		dstMap[c] = uint16(i)
	}
	return nil
}

func (x *fpeStringProcessor) SetTweak(tweak []byte) {
	var fpeModeWithSetTweak, ok = x.m.(fpeWithSetTweak)
	if !ok {
		panic("fpeStringProcessor/SetTweak: BlockMode must have a SetTweak function.")
	}
	fpeModeWithSetTweak.SetTweak(tweak)
}

func fromNumeralString(alphabetSlice []rune, numeralString []uint16) (string, error) {
	var out bytes.Buffer
	var alphabetSize = uint16(len(alphabetSlice))
	for i, num := range numeralString {
		if num < 0 || num >= alphabetSize {
			return "", fmt.Errorf("fromNumeralString: Numeral %d at index %d not in alphabet range", num, i)
		}
		out.WriteRune(alphabetSlice[num])
	}
	return out.String(), nil
}

func toNumeralString(alphabetMap map[rune]uint16, str string) ([]uint16, error) {
	var strSize = len(str)
	var numeralString = make([]uint16, strSize)

	for i, r := range str {
		_, validKey := alphabetMap[r]
		if !validKey {
			return nil, fmt.Errorf("toNumeralString: Character '%q' at index %d not in alphabet", r, i)
		}
		numeralString[i] = alphabetMap[r]
	}

	return numeralString, nil
}