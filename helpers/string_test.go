package helper

import (
	"testing"
	"strings"
	"crypto/aes"
	"crypto-fpe/fpe"
	"reflect"
)

var ff3CommonTweak1 = []byte{0xd8, 0xe7, 0x92, 0x0a, 0xfa, 0x33, 0x0a, 0x73}
var ff3CommonTweak2 = []byte{0x9a, 0x76, 0x8a, 0x92, 0xf6, 0x0e, 0x12, 0xd8}
var ff3CommonTweak3 = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
var ff3CommonKey128 = []byte{0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f, 0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94}
var ff3CommonKey192 = []byte{
	0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f, 0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
}
var ff3CommonKey256 = []byte{
	0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f, 0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94,
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
}

var stringEncryptionTests = []struct {
	name 		string
	key   		[]byte
	tweak 		[]byte
	alphabet	string
	in			string
	out			string
}{
	{
		"Sample #1",
		ff3CommonKey128,
		ff3CommonTweak1,
		"0123456789",
		"890121234567890000",
		"750918814058654607",

	},
	{
		"Sample #2",
		ff3CommonKey128,
		ff3CommonTweak2,
		"0123456789",
		"890121234567890000",
		"018989839189395384",
	},
	{
		"Sample #3",
		ff3CommonKey128,
		ff3CommonTweak1,
		"0123456789",
		"89012123456789000000789000000",
		"48598367162252569629397416226",
	},
	{
		"Sample #4",
		ff3CommonKey128,
		ff3CommonTweak3,
		"0123456789",
		"89012123456789000000789000000",
		"34695224821734535122613701434",
	},
	{
		"Sample #5",
		ff3CommonKey128,
		ff3CommonTweak2,
		"0123456789abcdefghijklmnop",
		"0123456789abcdefghi",
		"g2pk40i992fn20cjakb",
	},
	{
		"Sample #6",
		ff3CommonKey192,
		ff3CommonTweak1,
		"0123456789",
		"890121234567890000",
		"646965393875028755",
	},
	{
		"Sample #7",
		ff3CommonKey192,
		ff3CommonTweak2,
		"0123456789",
		"890121234567890000",
		"961610514491424446",
	},
	{
		"Sample #8",
		ff3CommonKey192,
		ff3CommonTweak1,
		"0123456789",
		"89012123456789000000789000000",
		"53048884065350204541786380807",
	},
	{
		"Sample #9",
		ff3CommonKey192,
		ff3CommonTweak3,
		"0123456789",
		"89012123456789000000789000000",
		"98083802678820389295041483512",
	},
	{
		"Sample #10",
		ff3CommonKey192,
		ff3CommonTweak2,
		"0123456789abcdefghijklmnop",
		"0123456789abcdefghi",
		"i0ihe2jfj7a9opf9p88",
	},
	{
		"Sample #11",
		ff3CommonKey256,
		ff3CommonTweak1,
		"0123456789",
		"890121234567890000",
		"922011205562777495",
	},
	{
		"Sample #12",
		ff3CommonKey256,
		ff3CommonTweak2,
		"0123456789",
		"890121234567890000",
		"504149865578056140",
	},
	{
		"Sample #13",
		ff3CommonKey256,
		ff3CommonTweak1,
		"0123456789",
		"89012123456789000000789000000",
		"04344343235792599165734622699",
	},
	{
		"Sample #14",
		ff3CommonKey256,
		ff3CommonTweak3,
		"0123456789",
		"89012123456789000000789000000",
		"30859239999374053872365555822",
	},
	{
		"Sample #15",
		ff3CommonKey256,
		ff3CommonTweak2,
		"0123456789abcdefghijklmnop",
		"0123456789abcdefghi",
		"p0b2godfja9bhb7bk38",
	},
}

var setAlphabetTests = []struct {
	alphabet	string
	valid		bool
}{
	{
		"abcdefghijklmnopqrstuvwxyz",
		true,
	},
	{
		"0123456789",
		true,
	},
	{
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ ",
		true,
	},
	{
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ +-*%&/()=?",
		true,
	},
	{
		"abcdefghijklmnopqrstuvwxyza",
		false,
	},
}

var numeralStringConversionTests = []struct {
	alphabet		string
	numeralString	[]uint16
	str				string
	valid 			bool
}{
	{
		"abcdefghijklmnopqrstuvwxyz",
		[]uint16{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25},
		"abcdefghijklmnopqrstuvwxyz",
		true,
	},
	{
		"abcdefghijklmnopqrstuvwxyz",
		[]uint16{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
		"zyxwvutsrqponmlkjihgfedcba",
		true,
	},
	{
		"abcdefghijklmnopqrstuvwxyz !",
		[]uint16{7, 4, 11, 11, 14, 26, 22, 14, 17, 11, 3, 27},
		"hello world!",
		true,
	},
	{
		"abcdefghijklmnopqrstuvwxyz",
		[]uint16{0, 1, 26},
		"ab!",
		false,
	},
}

func TestEncryptString(t *testing.T) {
	for _, test := range stringEncryptionTests {
		var key = fpe.RevB(test.key)
		var aesBlock, err = aes.NewCipher(key)
		if err != nil {
			t.Errorf("%s(%s): NewCipher = %s", t.Name(), test.name, err)
			continue
		}

		var encrypter = fpe.NewFF3Encrypter(aesBlock, test.tweak, uint32(len(test.alphabet)))
		var strEncrypter = NewFpeStringProcessor(encrypter, test.alphabet)

		var out, errEnc = strEncrypter.Crypt(test.in)
		if errEnc != nil {
			t.Errorf("%s: %s", t.Name(), errEnc)
		}
		if strings.Compare(out, test.out) != 0 {
			t.Errorf("%s:\nhave %s\nwant %s", t.Name(), out, test.out)
		}
	}
}

func TestEncryptDecryptString(t *testing.T) {
	for _, test := range stringEncryptionTests {
		var key = fpe.RevB(test.key)
		var aesBlock, err = aes.NewCipher(key)
		if err != nil {
			t.Errorf("%s(%s): NewCipher = %s", t.Name(), test.name, err)
			continue
		}

		var encrypter = fpe.NewFF3Encrypter(aesBlock, test.tweak, uint32(len(test.alphabet)))
		var strEncrypter = NewFpeStringProcessor(encrypter, test.alphabet)

		// Encrypt
		var enc, errEnc = strEncrypter.Crypt(test.in)
		if errEnc != nil {
			t.Errorf("%s: %s", t.Name(), errEnc)
			continue
		}

		// Set FPE algo (FF3) for decryption
		var decrypter = fpe.NewFF3Decrypter(aesBlock, test.tweak, uint32(len(test.alphabet)))
		var strDecrypter = NewFpeStringProcessor(decrypter, test.alphabet)

		// Decrypt
		var dec, errDec = strDecrypter.Crypt(enc)
		if errDec != nil {
			t.Errorf("%s: %s", t.Name(), errDec)
			continue
		}
		if strings.Compare(dec, test.in) != 0 {
			t.Errorf("%s:\nhave %s\nwant %s", t.Name(), dec, test.in)
		}
	}
}

func TestEncryptStringWithDifferentTweaks(t *testing.T) {
	for _, test := range stringEncryptionTests {
		var key= fpe.RevB(test.key)
		var aesBlock, err = aes.NewCipher(key)
		if err != nil {
			t.Errorf("%s(%s): NewCipher = %s", t.Name(), test.name, err)
			continue
		}

		// Set FPE algo (FF3) for encryption
		var encrypter = fpe.NewFF3Encrypter(aesBlock, test.tweak, uint32(len(test.alphabet)))
		var strEncrypter = NewFpeStringProcessor(encrypter, test.alphabet)

		// Encrypt with first tweak
		var encTweak1, errEncTweak1 = strEncrypter.Crypt(test.in)
		if errEncTweak1 != nil {
			t.Error(errEncTweak1)
			continue
		}

		// Encrypt with second tweak
		var differentTweak = make([]byte, len(test.tweak))
		copy(differentTweak, test.tweak)
		differentTweak[0] ^= 1
		strEncrypter.SetTweak(differentTweak)
		var encTweak2, errEncTweak2 = strEncrypter.Crypt(test.in)
		if errEncTweak2 != nil {
			t.Error(errEncTweak2)
			continue
		}

		if strings.Compare(encTweak1, encTweak2) == 0 {
			t.Errorf("TestEncryptStringWithDifferentTweaks: The ciphertexts should be different")
		}
	}
}

func TestSetAlphabet(t *testing.T) {
	for _, test := range setAlphabetTests {
		var alphabetSize = len(test.alphabet)
		var alphabetMap = make(map[rune]uint16)
		var alphabetSlice = make([]rune, alphabetSize)

		var err = SetAlphabet(alphabetMap, alphabetSlice, test.alphabet)

		if test.valid && err != nil {
			t.Error(err)
		}
	}
}

func TestFromNumeralString(t *testing.T) {
	for _, test := range numeralStringConversionTests {
		var alphabetSize = len(test.alphabet)
		var alphabetMap = make(map[rune]uint16)
		var alphabetSlice = make([]rune, alphabetSize)
		var e = SetAlphabet(alphabetMap, alphabetSlice, test.alphabet)
		if e != nil {
			t.Errorf("SetAlphabet: %s", e)
			continue
		}
		var str, err = fromNumeralString(alphabetSlice, test.numeralString)

		if test.valid {
			if err != nil {
				t.Error(err)
			}
			if strings.Compare(str, test.str) != 0 {
				t.Errorf("FromNumeralString\nhave %s\nwant %s", str, test.str)
			}
		} else {
			if err == nil {
				t.Error("FromNumeralString should fail")
			}
		}
	}
}

func TestToNumeralString(t *testing.T) {
	for _, test := range numeralStringConversionTests {
		var alphabetSize = len(test.alphabet)
		var alphabetMap = make(map[rune]uint16)
		var alphabetSlice = make([]rune, alphabetSize)
		var e = SetAlphabet(alphabetMap, alphabetSlice, test.alphabet)
		if e != nil {
			t.Errorf("SetAlphabet: %s", e)
			continue
		}
		var numStr, err = toNumeralString(alphabetMap, test.str)


		if test.valid {
			if err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(numStr, test.numeralString) {
				t.Errorf("ToNumeralString\nhave %s\nwant %s", numStr, test.numeralString)
			}
		} else {
			if err == nil {
				t.Error("ToNumeralString should fail")
			}
		}
	}
}
