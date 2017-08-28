package helper

import (
	"testing"
	"crypto/aes"
	"crypto-fpe/fpe"
	"strings"
	"crypto/rand"
	"crypto/cipher"
)

var commonTweak = []byte{0xd8, 0xe7, 0x92, 0x0a, 0xfa, 0x33, 0x0a, 0x73}
var commonKey128 = []byte{0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f, 0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a, 0x94}

var luhnChecksumTests = []struct {
	creditcardStr string
	creditcard	  []uint16
}{
	// List of credit cards of different length taken from
	// http://www.freeformatter.com/credit-card-number-generator-validator.html
	{
		"5503059576140641",
		[]uint16{5, 5, 0, 3, 0, 5, 9, 5, 7, 6, 1, 4, 0, 6, 4, 1},
	},
	{
		"5190875267775587",
		[]uint16{5, 1, 9, 0, 8, 7, 5, 2, 6, 7, 7, 7, 5, 5, 8, 7},
	},
	{
		"5388430691619316",
		[]uint16{5, 3, 8, 8, 4, 3, 0, 6, 9, 1, 6, 1, 9, 3, 1, 6},
	},
	{
		"5259716362849968",
		[]uint16{5, 2, 5, 9, 7, 1, 6, 3, 6, 2, 8, 4, 9, 9, 6, 8},
	},
	{
		"4485931907561",
		[]uint16{4, 4, 8, 5, 9, 3, 1, 9, 0, 7, 5, 6, 1},
	},
	{
		"4539906229292",
		[]uint16{4, 5, 3, 9, 9, 0, 6, 2, 2, 9, 2, 9, 2},
	},
	{
		"4929648539647",
		[]uint16{4, 9, 2, 9, 6, 4, 8, 5, 3, 9, 6, 4, 7},
	},
	{
		"30548631649458",
		[]uint16{3, 0, 5, 4, 8, 6, 3, 1, 6, 4, 9, 4, 5, 8},
	},
	{
		"30140730833140",
		[]uint16{3, 0, 1, 4, 0, 7, 3, 0, 8, 3, 3, 1, 4, 0},
	},
	{
		"30057384948596",
		[]uint16{3, 0, 0, 5, 7, 3, 8, 4, 9, 4, 8, 5, 9, 6},
	},
	{
		"342360002246846",
		[]uint16{3, 4, 2, 3, 6, 0, 0, 0, 2, 2, 4, 6, 8, 4, 6},
	},
	{
		"372163472691951",
		[]uint16{3, 7, 2, 1, 6, 3, 4, 7, 2, 6, 9, 1, 9, 5, 1},
	},
	{
		"346784502512306",
		[]uint16{3, 4, 6, 7, 8, 4, 5, 0, 2, 5, 1, 2, 3, 0, 6},
	},
	{
		"5172281013676405",
		[]uint16{5, 1, 7, 2, 2, 8, 1, 0, 1, 3, 6, 7, 6, 4, 0, 5},
	},
	{
		"2720991964870138",
		[]uint16{2, 7, 2, 0, 9, 9, 1, 9, 6, 4, 8, 7, 0, 1, 3, 8},
	},
	{
		"5544428650661601",
		[]uint16{5, 5, 4, 4, 4, 2, 8, 6, 5, 0, 6, 6, 1, 6, 0, 1},
	},
	{
		"4532062227789137",
		[]uint16{4, 5, 3, 2, 0, 6, 2, 2, 2, 7, 7, 8, 9, 1, 3, 7},
	},
	{
		"4532470729240782",
		[]uint16{4, 5, 3, 2, 4, 7, 0, 7, 2, 9, 2, 4, 0, 7, 8, 2},
	},
	{
		"4556610925696214078",
		[]uint16{4, 5, 5, 6, 6, 1, 0, 9, 2, 5, 6, 9, 6, 2, 1, 4, 0, 7, 8},
	},
	{
		"6011097525625220158",
		[]uint16{6, 0, 1, 1, 0, 9, 7, 5, 2, 5, 6, 2, 5, 2, 2, 0, 1, 5, 8},
	},
}

func TestEncryptDecryptCCWithFF3(t *testing.T) {
	for _, test := range luhnChecksumTests  {
		var key = make([]byte, 16)
		rand.Read(key)
		var tweak = make([]byte, 8)
		rand.Read(tweak)

		var aesBlock, err = aes.NewCipher(key)
		if err != nil {
			t.Errorf("%s: NewCipher = %s", t.Name(), err)
			continue
		}

		// Set FPE algo (FF3) for encryption
		var encrypter = fpe.NewFF3Encrypter(aesBlock, tweak, CCRadix)
		var creditCardEncrypter = NewFPECreditCardProcessor(encrypter)

		// Encrypt
		var enc, errEnc = creditCardEncrypter.Crypt(test.creditcardStr)
		if errEnc != nil {
			t.Errorf("%s: %s", t.Name(), errEnc)
			continue
		}

		// Set FPE algo (FF3) for decryption
		var decrypter = fpe.NewFF3Decrypter(aesBlock, tweak, CCRadix)
		var ccDecrypter = NewFPECreditCardProcessor(decrypter)

		// Decrypt
		var dec, errDec = ccDecrypter.Crypt(enc)
		if errDec != nil {
			t.Errorf("%s: %s", t.Name(), errDec)
			continue
		}

		// Compare results
		if strings.Compare(dec, test.creditcardStr) != 0 {
			t.Errorf("%s: \nhave %s\nwant %s", t.Name(), dec, test.creditcardStr)
		}
	}
}

func TestEncryptDecryptCCWithFF1(t *testing.T) {
	for _, test := range luhnChecksumTests  {
		var key = make([]byte, 16)
		rand.Read(key)
		var tweak = make([]byte, 20)
		rand.Read(tweak)

		var aesBlock, err = aes.NewCipher(key)
		if err != nil {
			t.Errorf("%s: NewCipher = %s", t.Name(), err)
			continue
		}

		var iv = make([]byte, 16)
		var cbcMode = cipher.NewCBCEncrypter(aesBlock, iv)

		// Set FPE algo (FF1) for encryption
		var encrypter = fpe.NewFF1Encrypter(aesBlock, cbcMode, tweak, CCRadix)
		var creditCardEncrypter = NewFPECreditCardProcessor(encrypter)

		// Encrypt
		var enc, errEnc = creditCardEncrypter.Crypt(test.creditcardStr)
		if errEnc != nil {
			t.Errorf("%s: %s", t.Name(), errEnc)
			continue
		}

		// Set FPE algo (FF1) for decryption
		var decrypter = fpe.NewFF1Decrypter(aesBlock, cbcMode, tweak, CCRadix)
		var ccDecrypter = NewFPECreditCardProcessor(decrypter)

		// Decrypt
		var dec, errDec = ccDecrypter.Crypt(enc)
		if errDec != nil {
			t.Errorf("%s: %s", t.Name(), errDec)
			continue
		}

		// Compare results
		if strings.Compare(dec, test.creditcardStr) != 0 {
			t.Errorf("%s: \nhave %s\nwant %s", t.Name(), dec, test.creditcardStr)
		}
	}
}

func TestLuhnChecksum(t *testing.T) {
	for _, test := range luhnChecksumTests  {
		var l = len(test.creditcard)
		var creditcard = test.creditcard[:l-1]
		var expectedChecksum = test.creditcard[l-1:]

		var checksum = luhnChecksum(creditcard)

		if checksum != expectedChecksum[0] {
			t.Errorf("%s:\nhave %d\nwant %d", t.Name(), checksum, expectedChecksum[0])
		}
	}
}

func TestValidateLuhnChecksum(t *testing.T) {
	for _, test := range luhnChecksumTests  {
		var creditcard = test.creditcard

		var isChecksumValid = validateChecksum(creditcard)

		if !isChecksumValid {
			t.Errorf("%s: LuhnChecksum is incorrect", t.Name())
		}
	}
}

func TestSetTweak(t *testing.T) {
	type fpeCCWithTweak interface {
		Crypt(src string) (string, error)
		SetTweak([]byte)
	}
	var key = make([]byte, 16)
	// Get two different tweaks
	var tweak = make([]byte, 8)
	var iv = make([]byte, 16)

	var aesBlock, err = aes.NewCipher(key)
	if err != nil {
		t.Errorf("%s: NewCipher = %s", t.Name(), err)
	}

	var cbcMode = cipher.NewCBCEncrypter(aesBlock, iv)
	var ff1Encrypter = fpe.NewFF1Encrypter(aesBlock, cbcMode, tweak, CCRadix)
	var ff1Decrypter = fpe.NewFF1Decrypter(aesBlock, cbcMode, tweak, CCRadix)
	var ff3Encrypter = fpe.NewFF3Encrypter(aesBlock, tweak, CCRadix)
	var ff3Decrypter = fpe.NewFF3Decrypter(aesBlock, tweak, CCRadix)

	var ff1CreditCardEncrypter = NewFPECreditCardProcessor(ff1Encrypter)
	var ff1CreditCardDecrypter = NewFPECreditCardProcessor(ff1Decrypter)
	var ff3CreditCardEncrypter = NewFPECreditCardProcessor(ff3Encrypter)
	var ff3CreditCardDecrypter = NewFPECreditCardProcessor(ff3Decrypter)

	var ff1EncTweak, okFF1Enc = ff1CreditCardEncrypter.(fpeCCWithTweak)
	if !okFF1Enc {
		t.Errorf("%s: fpeCreditCardProcessor has no SetTweak function", t.Name())
	}
	var ff1DecTweak, okFF1Dec = ff1CreditCardDecrypter.(fpeCCWithTweak)
	if !okFF1Dec {
		t.Errorf("%s: fpeCreditCardProcessor has no SetTweak function", t.Name())
	}
	var ff3EncTweak, okFF3Enc = ff3CreditCardEncrypter.(fpeCCWithTweak)
	if !okFF3Enc {
		t.Errorf("%s: fpeCreditCardProcessor has no SetTweak function", t.Name())
	}
	var ff3DecTweak, okFF3Dec = ff3CreditCardDecrypter.(fpeCCWithTweak)
	if !okFF3Dec {
		t.Errorf("%s: fpeCreditCardProcessor has no SetTweak function", t.Name())
	}
	var otherTweak = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ff3EncTweak.SetTweak(otherTweak)
	ff3DecTweak.SetTweak(otherTweak)
	ff1EncTweak.SetTweak(otherTweak)
	ff1DecTweak.SetTweak(otherTweak)
}

func TestCreditCardSeparators(t *testing.T) {
	var key = make([]byte, 16)
	rand.Read(key)
	var tweak = make([]byte, 8)
	rand.Read(tweak)

	var aesBlock, err = aes.NewCipher(key)
	if err != nil {
		t.Errorf("%s: NewCipher = %s", t.Name(), err)
	}

	// Set FPE algo (FF3) for encryption
	var encrypter = fpe.NewFF3Encrypter(aesBlock, tweak, CCRadix)
	var creditCardEncrypter = NewFPECreditCardProcessor(encrypter)
	// Set FPE algo (FF3) for decryption
	var decrypter = fpe.NewFF3Decrypter(aesBlock, tweak, CCRadix)
	var ccDecrypter = NewFPECreditCardProcessor(decrypter)

	var ccNumbers = []string{
		"5503059576140641", "5503 0595 7614 0641", "-5503-0595-7614-0641-", "55&03_0595__76_14-06!41",
		"5503��0595��761��406��41", "5503⌘0595⌘76140⌘⌘641", "5503日0595本7614語0641", "5503日本語0595日本語7614日本語0641"}
	for _, cc := range ccNumbers {
		// Encrypt
		var enc, errEnc = creditCardEncrypter.Crypt(cc)
		if errEnc != nil {
			t.Errorf("%s: %s", t.Name(), errEnc)
		}
		// Decrypt
		var dec, errDec = ccDecrypter.Crypt(enc)
		if errDec != nil {
			t.Errorf("%s: %s", t.Name(), errDec)
		}
		// Compare results
		if strings.Compare(dec, cc) != 0 {
			t.Errorf("%s: \nhave %s\nwant %s", t.Name(), dec, cc)
		}
		// Check separators
		for i := 0; i < len(cc); i++ {
			// Select chars that are not numbers
			if cc[i] < 48 || cc[i] > 57 {
				if cc[i] != enc[i] {
					t.Errorf("%s: Wrong separators in %s (plaintext: %s).", t.Name(), dec, enc)
				}
			}
		}
	}
}


