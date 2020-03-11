package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"
	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	// strconv

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
  var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a file record
type File struct {
	SharingRecordUUID uuid.UUID
	SharingEncKey []byte
	SharingHMACKey []byte
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	RsaPrivate userlib.PKEDecKey
	DSSignPrivateKey userlib.DSSignKey
	Files map[string]File
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	// RSA and Digital Signature Keys Generation.
	rsaPublic, rsaPrivate, err_1 := userlib.PKEKeyGen()
	dsPrivate, dsPublic, err_2 := userlib.DSKeyGen()

	// Create userdata struct
	userdata := User{username, password, rsaPrivate, dsPrivate, make(map[string]File)}
	userdataptr = &userdata

	// Store userdata and keys to the servers.
	userUUID, userCipher, err_3 := EncryptUser(userdataptr)
	userlib.DatastoreSet(userUUID, userCipher)
	err_4 := userlib.KeystoreSet(username + "PK", rsaPublic)
	err_5 := userlib.KeystoreSet(username + "DS", dsPublic)

	// error checking.
	for _, err := range []error{err_1, err_2, err_3, err_4, err_5} {
		if err != nil { return nil, err }
	}

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	usernameByte, err_1 := json.Marshal(username)
	passwordByte, err_2 := json.Marshal(password)

	uuidSalt, err_3 := json.Marshal(username + "UUID")
	symKeySalt, err_4 := json.Marshal(username + "ENC")
	hmacKeySalt, err_5 := json.Marshal(username+ "DataHMAC")

	for _, err := range []error{err_1, err_2, err_3, err_4, err_5} {
		if err != nil { return nil, err }
	}

	argKeyMaster := userlib.Argon2Key(passwordByte, usernameByte, 16)
	uuidByte := userlib.Argon2Key(argKeyMaster, uuidSalt, 16)
	symKey := userlib.Argon2Key(argKeyMaster, symKeySalt, 16)
	hmacKey := userlib.Argon2Key(argKeyMaster, hmacKeySalt, 16)

	userUUID := bytesToUUID(uuidByte)

	userCipher, ok := userlib.DatastoreGet(userUUID)
	if !ok { return nil, errors.New("Incorrect Username Or Password") }

	userdataByte, err := DecryptCipher(symKey, hmacKey, userCipher)
	if err != nil { return nil, err }

	json.Unmarshal(userdataByte, userdataptr)

	return userdataptr, nil
}

// This stores a file in the datastore.
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
  //Creating uuids.
	fileDataUUID := uuid.New()
	sharingRecordUUID := uuid.New()

	// Generating four symmetric keys.
	sharingRecordEncKey, _ := randomKey()
	sharingRecordHMACKey, _ := randomKey()
	fileDataEncKey, _ := randomKey()
	fileDataHMACKey, _ := randomKey()

	// Encrypts & HMACs file data.
	fileDataCipher, _ := SymEncHMACConcat(fileDataEncKey, fileDataHMACKey, data)

	// Construct File & sharingRecord struct
	sharingRecord := sharingRecord{userdata.Username, []uuid.UUID{fileDataUUID}, fileDataEncKey, fileDataHMACKey}
	file := File{sharingRecordUUID, sharingRecordEncKey, sharingRecordHMACKey}

	// Encrypts & HMACs sharingRecord
	sharingRecordByte, _ := json.Marshal(sharingRecord)
	sharingRecordCipher, _ := SymEncHMACConcat(sharingRecordEncKey, sharingRecordHMACKey, sharingRecordByte)

	// Update userdata
	userdata.Files[filename] = file
	userUUID, userCipher, _ := EncryptUser(userdata)
	userlib.DatastoreSet(userUUID, userCipher)

	// Upload file data and sharingRecord to DataStore
	userlib.DatastoreSet(fileDataUUID, fileDataCipher)
	userlib.DatastoreSet(sharingRecordUUID, sharingRecordCipher)

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	sharingPtr, err := userdata.GetSharingRecord(filename)
	if err != nil { return err } // file does not exit.

	newFileDataUUID := uuid.New()

	// Generating keys
	newFileDataEncKey, err_1 := randomKey()
	newFileDataHMACKey, err_2 := randomKey()

	// Encrypt & HMAC new Data
	newFileCipher, err_3 := SymEncHMACConcat(newFileDataEncKey, newFileDataHMACKey, data)

	// Update sharingRecord
	sharingPtr.FileDataUUID = append(sharingPtr.FileDataUUID, newFileDataUUID)
	sharingPtr.FileDataEncKey = append(sharingPtr.FileDataEncKey, newFileDataEncKey...)
	sharingPtr.FileDataHMACKey = append(sharingPtr.FileDataHMACKey, newFileDataHMACKey...)
	sharingRecordByte, err_4 := json.Marshal(*sharingPtr)
	fileStruct, _ := userdata.Files[filename]
	sharingRecordCipher, err_5 := SymEncHMACConcat(fileStruct.SharingEncKey, fileStruct.SharingHMACKey, sharingRecordByte)

	for _, err := range []error{err_1, err_2, err_3, err_4, err_5} {
		if err != nil { return err }
	}

	userlib.DatastoreSet(fileStruct.SharingRecordUUID, sharingRecordCipher)
	userlib.DatastoreSet(newFileDataUUID, newFileCipher)

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	sharingPtr, err := userdata.GetSharingRecord(filename)
	if err != nil { return nil, err }

	fileData := make([]byte, 0)
	if len(sharingPtr.FileDataEncKey) != 16 * len(sharingPtr.FileDataUUID) {
		return nil, errors.New("Not Enough Decryption Key")
	}
	if len(sharingPtr.FileDataHMACKey) != 16 * len(sharingPtr.FileDataUUID) {
		return nil, errors.New("Not Enough Decryption Key")
	}
	for i, FileUUID := range sharingPtr.FileDataUUID {
		fileCipher, ok := userlib.DatastoreGet(FileUUID)
		if !ok { return nil, errors.New("File Not Found")}
		start, end := i*16, i*16 + 16
		filePlain, err := DecryptCipher(sharingPtr.FileDataEncKey[start:end], sharingPtr.FileDataHMACKey[start:end], fileCipher)
		if err != nil { return nil, err }
		fileData = append(fileData, filePlain...)
	}

	// MergeFile
	fileDataUUID := uuid.New()

	fileDataEncKey, err_1 := randomKey()
	fileDataHMACKey, err_2 := randomKey()

	fileDataCipher, err_3 := SymEncHMACConcat(fileDataEncKey, fileDataHMACKey, fileData)

	for _, FileUUID := range sharingPtr.FileDataUUID {
		userlib.DatastoreDelete(FileUUID)
	}

	sharingPtr.FileDataUUID = []uuid.UUID{fileDataUUID}
	sharingPtr.FileDataEncKey = fileDataEncKey
	sharingPtr.FileDataHMACKey = fileDataHMACKey

	fileStruct, _ := userdata.Files[filename]
	sharingRecordByte, err_4 := json.Marshal(*sharingPtr)
	sharingRecordCipher, err_5 := SymEncHMACConcat(fileStruct.SharingEncKey, fileStruct.SharingHMACKey, sharingRecordByte)

	for _, err := range []error{err_1, err_2, err_3, err_4, err_5} {
		if err != nil { return nil, err }
	}

	userlib.DatastoreSet(fileDataUUID, fileDataCipher)
	userlib.DatastoreSet(fileStruct.SharingRecordUUID, sharingRecordCipher)

	return fileData, nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
		Creator string
		FileDataUUID []uuid.UUID
		FileDataEncKey []byte
		FileDataHMACKey []byte
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {
		err = userdata.MergeFile(filename)
		if err != nil { return "", err }

		recipientPK, ok := userlib.KeystoreGet(recipient + "PK")
		if !ok { return "", errors.New("Public Key Not Found") }

		sessionKey, err_1 := randomKey()
		sessionKeyCipher, err_2 := userlib.PKEEnc(recipientPK, sessionKey)

		fileStruct, _ := userdata.Files[filename]
		fileStructByte, err_3 := json.Marshal(fileStruct)

		iv, err_4 := randomKey()
		fileStructCipher := userlib.SymEnc(sessionKey, iv, fileStructByte)
		sign, err_5 := userlib.DSSign(userdata.DSSignPrivateKey, fileStructByte)

		var magic_stringByte []byte
		magic_stringByte = append(magic_stringByte, sessionKeyCipher...)
		magic_stringByte = append(magic_stringByte, sign...)
		magic_stringByte = append(magic_stringByte, fileStructCipher...)

		magic_string = hex.EncodeToString(magic_stringByte)

		for _, err := range []error{err_1, err_2, err_3, err_4, err_5} {
			if err != nil { return "", nil }
		}

	return magic_string, nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {

		senderVerifyKey, ok := userlib.KeystoreGet(sender + "DS")
		if !ok {return errors.New("Public Key Not Found")}

		magic_stringByte, err_1 := hex.DecodeString(magic_string)

		if len(magic_stringByte) < 513 { return errors.New("Magic String Out of Bounds") } // Integrity Fails
		sessionKey, err_2 := userlib.PKEDec(userdata.RsaPrivate, magic_stringByte[:256])
		if len(sessionKey) != 16 { return errors.New("Wrong Key Size") }
		fileStructByte := userlib.SymDec(sessionKey, magic_stringByte[512:])
		err_3 := userlib.DSVerify(senderVerifyKey, fileStructByte, magic_stringByte[256:512])

		var fileStruct File
		fileStructPtr := &fileStruct

		json.Unmarshal(fileStructByte, fileStructPtr)

		userdata.Files[filename] = fileStruct
		userUUID, userCipher, err_4 := EncryptUser(userdata)

		for _, err := range []error{err_1, err_2, err_3, err_4} {
			if err != nil { return err }
		}

		userlib.DatastoreSet(userUUID, userCipher)

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	sharingPtr, err := userdata.GetSharingRecord(filename)
	if err != nil { return err }

	if sharingPtr.Creator != userdata.Username {
		return errors.New("Permission Denied")
	}

	fileData, err := userdata.LoadFile(filename)
	if err != nil { return err }

	for _, FileUUID := range sharingPtr.FileDataUUID {
		userlib.DatastoreDelete(FileUUID)
	}
	fileStruct, _ := userdata.Files[filename]
	userlib.DatastoreDelete(fileStruct.SharingRecordUUID)
	delete(userdata.Files, filename)

	userdata.StoreFile(filename, fileData)
	return nil
}

// Takes plaintext and two keys (encryption key, HMAC key)
// Returns (ciphertext || HMAC, error)
func SymEncHMACConcat(encKey []byte, hmacKey []byte, plaintext []byte) ([]byte, error) {
	iv, err_1 := randomKey()
	iv = iv[:16]
	ciphertext := userlib.SymEnc(encKey, iv, plaintext)
	ciphertextHMAC, err_2 := userlib.HMACEval(hmacKey, ciphertext)
	concatenated := append(ciphertext, ciphertextHMAC...)
	for _, err := range []error{err_1, err_2} {
		if err != nil {
			return nil, err
		}
	}
	return concatenated, nil
}

// Takes User struct pointer
// It encrypt userdata & HMAC it, then store into Datastore
func EncryptUser(userdata *User) (uuid.UUID, []byte, error) {
	usernameByte, err_1 := json.Marshal(userdata.Username)
	passwordByte, err_2 := json.Marshal(userdata.Password)

	// Create Salts
	uuidSalt, err_3 := json.Marshal(userdata.Username + "UUID")
	symKeySalt, err_4 := json.Marshal(userdata.Username + "ENC")
	hmacKeySalt, err_5 := json.Marshal(userdata.Username + "DataHMAC")

	// Generating Keys
  argKeyMaster := userlib.Argon2Key(passwordByte, usernameByte, 16)
	uuidByte := userlib.Argon2Key(argKeyMaster, uuidSalt, 16)
	symKey := userlib.Argon2Key(argKeyMaster, symKeySalt, 16)
	hmacKey := userlib.Argon2Key(argKeyMaster, hmacKeySalt, 16)

	// Encrypt & HMAC userdata
	userdataByte, err_6 := json.Marshal(*userdata)
	userCipher, err_7 := SymEncHMACConcat(symKey, hmacKey, userdataByte)

	// Error checking
	for _, err := range []error{err_1, err_2, err_3, err_4, err_5, err_6, err_7} {
		if err != nil {	return uuid.Nil, nil, err }
	}

	userUUID := bytesToUUID(uuidByte)
	return userUUID, userCipher, nil
}

func DecryptCipher(symKey []byte, hmacKey []byte, ciphertext []byte) ([]byte, error){
	// Integrity check
	if len(ciphertext) - 64 < 0 { return nil, errors.New("Ciphertext Out of Bounds") } // Integrity Failed
	macValue, err := userlib.HMACEval(hmacKey, ciphertext[:len(ciphertext)-64])
	ok := userlib.HMACEqual(macValue, ciphertext[len(ciphertext)-64:])
	if !ok { return nil, errors.New("Integrity Failed") }
	if err != nil { return nil, err }
	return userlib.SymDec(symKey,ciphertext[:len(ciphertext)-64]), nil
}

func (userdata *User) GetSharingRecord(filename string) (*sharingRecord, error) {
	fileStruct, ok := userdata.Files[filename]
	if !ok { return nil, errors.New("File Not Found") }
	sharingCipher, ok := userlib.DatastoreGet(fileStruct.SharingRecordUUID)
	if !ok { return nil, errors.New("File Not Found") }

	// Integrity Check & Decrypt
	sharingByte, err := DecryptCipher(fileStruct.SharingEncKey, fileStruct.SharingHMACKey, sharingCipher)
	if err != nil { return nil, err }

	// Get sharingRecord Struct
	var sharing sharingRecord
	json.Unmarshal(sharingByte, &sharing)
	return &sharing, nil
}

func (userdata *User) MergeFile(filename string) error {
	fileData, err := userdata.LoadFile(filename)
	if err != nil { return err }

	fileDataUUID := uuid.New()

	fileDataEncKey, err_1 := randomKey()
	fileDataHMACKey, err_2 := randomKey()
	fileDataCipher, err_3 := SymEncHMACConcat(fileDataEncKey, fileDataHMACKey, fileData)

	sharingPtr, _ := userdata.GetSharingRecord(filename)

	for _, FileUUID := range sharingPtr.FileDataUUID {
		userlib.DatastoreDelete(FileUUID)
	}

	sharingPtr.FileDataUUID = []uuid.UUID{fileDataUUID}
	sharingPtr.FileDataEncKey = fileDataEncKey
	sharingPtr.FileDataHMACKey = fileDataHMACKey

	fileStruct, _ := userdata.Files[filename]
	sharingRecordByte, err_4 := json.Marshal(*sharingPtr)
	sharingRecordCipher, err_5 := SymEncHMACConcat(fileStruct.SharingEncKey, fileStruct.SharingHMACKey, sharingRecordByte)

	for _, err := range []error{err_1, err_2, err_3, err_4, err_5} {
		if err != nil { return err }
	}

	userlib.DatastoreSet(fileDataUUID, fileDataCipher)
	userlib.DatastoreSet(fileStruct.SharingRecordUUID, sharingRecordCipher)

	return nil
}

func (userdata *User) GetUserUUID() (uuid.UUID, error) {
	// This function is just for a debugging purpose.
	usernameByte, err_1 := json.Marshal(userdata.Username)
	passwordByte, err_2 := json.Marshal(userdata.Password)
	uuidSalt, err_3 := json.Marshal(userdata.Username + "UUID")
	argKeyMaster := userlib.Argon2Key(passwordByte, usernameByte, 16)
	uuidByte := userlib.Argon2Key(argKeyMaster, uuidSalt, 16)
	for _, err := range []error{err_1, err_2, err_3} {
		if err != nil { return uuid.Nil, err }
	}
	userUUID := bytesToUUID(uuidByte)
	return userUUID, nil
}

func randomKey() ([]byte, error) {
	key, err :=userlib.HMACEval(userlib.RandomBytes(16), userlib.RandomBytes(16))
	return key[:16], err
}
