# fpe-field-format

![travis ci status](https://travis-ci.org/cloudtrust/fpe-field-format.svg?branch=master)


This repository provides helpers to encipher various information such as credit cards, or string while preserving their format.
The helpers use a mode for format-preserving encryption like FF1 or FF3 provided in [this](https://github.com/cloudtrust/fpe) repository.

The credit card helper enciphers a credit card number and output a valid credit card, that is a credit card with valid Luhn checksum. If a character is used to separate or group digits, it is preserved in the ciphertext. For example if you encipher 5503 0595 7614 0641, the ciphertext will be of the form XXXX XXXX XXXX XXXX (i.e. 6046 4435 3565 0662). If you encipher 5503-0595-7614-0641, the ciphertext will be of the form XXXX-XXXX-XXXX-XXXX (i.e. 6046-4435-3565-0662). All non-digit characters are preserved.

The string helper takes as input the alphabet, that is the list of authorized characters. Then the plaintext and ciphertext will be composed of characters taken from this alphabet.

```golang
func stringTest() {
	var key = make([]byte, 16)
	rand.Read(key)
	var tweak = make([]byte, 20)
	rand.Read(tweak)

	var alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ !"
	var plaintext = "Hello World!"

	// Get FF1 Encrypter and Decrypter
	var ff1Encrypter = getFF1Encrypter(key, tweak, uint32(len(alphabet)))
	var ff1Decrypter = getFF1Decrypter(key, tweak, uint32(len(alphabet)))

	// Encrypt then decrypt string
	var strEncrypter = helper.NewFpeStringProcessor(ff1Encrypter, alphabet)
	var strDecrypter = helper.NewFpeStringProcessor(ff1Decrypter, alphabet)

	var ciphertext, _ = strEncrypter.Crypt(plaintext)
	var decrypted, _ = strDecrypter.Crypt(ciphertext)

	// Print values
	fmt.Printf("String example:\n")
	fmt.Printf("Plaintext:  %s\n", plaintext)
	fmt.Printf("Ciphertext: %s\n", ciphertext)
	fmt.Printf("Decrypted:  %s\n", decrypted)
}

func ccTest() {
	// FF1 Example
	var key = make([]byte, 16)
	rand.Read(key)
	var tweak = make([]byte, 20)
	rand.Read(tweak)

	var plaintext = "5503 0595 7614 0641"

	// Get FF1 Encrypter and Decrypter
	var ff1Encrypter = getFF1Encrypter(key, tweak, helper.CCRadix)
	var ff1Decrypter = getFF1Decrypter(key, tweak, helper.CCRadix)
	// Create Credit Card Encrypter and Decrypter
	var ccEncrypter = helper.NewFPECreditCardProcessor(ff1Encrypter)
	var ccDecrypter = helper.NewFPECreditCardProcessor(ff1Decrypter)

	// Encrypt then decrypt credit card number
	var ciphertext, _ = ccEncrypter.Crypt(plaintext)
	var decrypted, _ = ccDecrypter.Crypt(ciphertext)

	// Print values
	fmt.Printf("Credit Card example:\n")
	fmt.Printf("Plaintext:  %s\n", plaintext)
	fmt.Printf("Ciphertext: %s\n", ciphertext)
	fmt.Printf("Decrypted:  %s\n", decrypted)
}

func getFF1Encrypter(key, tweak []byte, radix uint32) (cipher.BlockMode) {
	// Create AES Block used by FF1.
	var aesBlock, err = aes.NewCipher(key)
	if err != nil {
		fmt.Printf("NewCipher = %s", err)
	}

	// Create CBC mode used by FF1.
	var iv = make([]byte, 16)
	var cbcMode = cipher.NewCBCEncrypter(aesBlock, iv)

	// Create FF1 Encrypter
	var encrypter = fpe.NewFF1Encrypter(aesBlock, cbcMode, tweak, radix)

	return encrypter
}

func getFF1Decrypter(key, tweak []byte, radix uint32) (cipher.BlockMode) {
	// Create AES Block used by FF1.
	var aesBlock, err = aes.NewCipher(key)
	if err != nil {
		fmt.Printf("NewCipher = %s", err)
	}

	// Create CBC mode used by FF1.
	var iv = make([]byte, 16)
	var cbcMode = cipher.NewCBCEncrypter(aesBlock, iv)

	// Create FF1 Decrypter
	var decrypter = fpe.NewFF1Decrypter(aesBlock, cbcMode, tweak, radix)

	return decrypter
}
```






