package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

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
	_ "strconv"

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

// The structure definition for a user record
type User struct {
	Username string
	PasswordHash []byte
	Salt []byte
	SymmetricKey []byte
	HmacKey []byte
	PrivateKey userlib.PKEDecKey
	SignKey userlib.DSSignKey
	Uuid uuid.UUID
	Files map[string]UserFile //maps filename to fsr uuid and fsrkey uuid

	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type UserFile struct {
	FsrUuid uuid.UUID
	FsrKeyUuid uuid.UUID
}

//type File struct {
//	Uuid uuid.UUID
//	SymmetricKey []byte
//	HmacKey []byte
//}

type FileData struct {
	MetaData []byte
	Data []byte
}

type MetaData struct {
	Shares []Share
	Appends []int
}

type Share struct {
	Sender string
	Recipient string
	FsrUuid uuid.UUID
	FsrKeyUuid uuid.UUID
}

type SharingRecord struct {
	HmacKey []byte //to ensure integrity
	FileUuid uuid.UUID
	FileSymmetricKey []byte
	FileHmacKey []byte
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
	var userdata User
	userdataptr = &userdata

	userdata.Files = make(map[string]UserFile)
	userdata.Username = username
	userdata.Salt = userlib.RandomBytes(16)

	//generate 32 byte key from password
	keyString := userlib.Argon2Key([]byte(password), userdata.Salt, 32)
	userdata.SymmetricKey = keyString[:16]
	userdata.HmacKey = keyString[16:]

	//generate user's key pairs
	publicKey,privateKey,_ := userlib.PKEKeyGen()
	signKey, verifyKey,_ := userlib.DSKeyGen()

	//write private Keys to userdata
	userdata.PrivateKey = privateKey
	userdata.SignKey = signKey

	//store public keys to keystore
	userlib.KeystoreSet(username+"pke", publicKey)
	userlib.KeystoreSet(username+"ds", verifyKey)

	//generate and store user uuid
	uuidString := userlib.Argon2Key([]byte(username+password), []byte(""), 16)
	userdata.Uuid,_ = uuid.FromBytes(uuidString)

	//encrypt userdata
	jsonUserdata,_ := json.Marshal(userdata)
	encrypted := userlib.SymEnc(userdata.SymmetricKey, userlib.RandomBytes(16), jsonUserdata)
	ciphertext := append(userdata.Salt, encrypted...)

	//hmac encrypted data
	hmac,_ := userlib.HMACEval(userdata.HmacKey, encrypted)
	securedData := append(hmac, ciphertext...)

	//store secured data to datastore
	userlib.DatastoreSet(userdata.Uuid, securedData)

	return userdataptr, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//retrieve secured data from datastore
	uuidString := userlib.Argon2Key([]byte(username+password), []byte(""), 16)
	userUuid,_ := uuid.FromBytes(uuidString)
	securedData,fileExist := userlib.DatastoreGet(userUuid)
	if !fileExist {
		return userdataptr, errors.New("invalid username/password")
	}
	hmac := securedData[:64]
	salt := securedData[64:80]
	ciphertext := securedData[80:]

	//generate 32 byte key from password
	keyString := userlib.Argon2Key([]byte(password), salt, 32)
	symmetricKey := keyString[:16]
	hmacKey := keyString[16:]

	//check if file is corrupted or tampered
	receivedHmac,_ := userlib.HMACEval(hmacKey, ciphertext)
	if !userlib.HMACEqual(hmac, receivedHmac) {
		return nil, errors.New("userdata corrupted")
	}

	//decrypt encrypted user data
	decrypted := userlib.SymDec(symmetricKey, ciphertext)
	err = json.Unmarshal(decrypted, userdataptr)
	if err != nil{
		return nil, errors.New("decrypt failed")
	}

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name and length of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//create file uuid
	fileUuidString := userlib.Argon2Key([]byte(userdata.Username+filename), []byte(""), 16)
	fileUuid,_ := uuid.FromBytes(fileUuidString)

	//create new keys to encrypt file
	keyString,_ := userlib.HMACEval(userlib.RandomBytes(16), data)
	symmetricKey := keyString[:16]
	hmacKey := keyString[16:32]

	//create file metadata
	var metaData MetaData
	metaData.Shares = make([]Share, 100)

	//encrypt file data with symmetric key
	encryptedFile := userlib.SymEnc(symmetricKey, userlib.RandomBytes(16), data)
	hmacFile,_ := userlib.HMACEval(hmacKey, encryptedFile)
	secured := append(hmacFile, encryptedFile...)

	//update file metadata
	metaData.Appends = append(metaData.Appends, len(secured))
	marshalledMetaData,_ := json.Marshal(metaData)

	//encrypt file metadata with symmetric key
	encryptedMetaData := userlib.SymEnc(symmetricKey, userlib.RandomBytes(16), marshalledMetaData)
	hmacMetaData,_ := userlib.HMACEval(hmacKey, encryptedMetaData)
	securedMetaData := append(hmacMetaData, encryptedMetaData...)

	//create file data
	var fileData FileData
	fileData.Data = secured
	fileData.MetaData = securedMetaData
	marshalledFileData,_ := json.Marshal(fileData)

	//store file to datastore
	userlib.DatastoreSet(fileUuid, marshalledFileData)

	//generate uuid for sharing record
	srUuidSeed := userlib.Argon2Key([]byte(userdata.Username+userdata.Username+filename),
		userlib.RandomBytes(16), 32)
	srUuid,_ := uuid.FromBytes(srUuidSeed[:16])
	fsrKey := srUuidSeed[16:]

	//create file sharing record
	userdata.CreateNewFileSharingRecord(srUuid, fileUuid, symmetricKey, hmacKey,fsrKey)

	//create fsrkeyrecord
	encryptedFsrKeyUuid := uuid.New()
	userdata.CreateFSRKeyDump(userdata.Username, fsrKey, encryptedFsrKeyUuid)

	//update files in userdata
	var userFile UserFile
	userFile.FsrKeyUuid = encryptedFsrKeyUuid
	userFile.FsrUuid = srUuid
	userdata.Files[filename] = userFile

	//encrypt userdata
	jsonUserdata,_ := json.Marshal(userdata)
	encrypted := userlib.SymEnc(userdata.SymmetricKey, userlib.RandomBytes(16), jsonUserdata)
	ciphertext := append(userdata.Salt, encrypted...)

	//hmac encrypted data
	hmac,_ := userlib.HMACEval(userdata.HmacKey, encrypted)
	securedData := append(hmac, ciphertext...)

	//store secured data to datastore
	userlib.DatastoreSet(userdata.Uuid, securedData)

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	//retrieve file information from filename
	userFile := userdata.Files[filename]
	fsrKeyUuid := userFile.FsrKeyUuid
	fsrUuid := userFile.FsrUuid

	//retrieve encrypted fsr key
	encryptedFsrKey,_ := userlib.DatastoreGet(fsrKeyUuid)

	//decrypt encrypted fsr key
	fsrKey,_ := userlib.PKEDec(userdata.PrivateKey, encryptedFsrKey)

	//retrieve secured fsr
	securedFsr,_ := userlib.DatastoreGet(fsrUuid)

	var sharingRecord SharingRecord
	decryptedSR := userlib.SymDec(fsrKey, securedFsr[64:])
	json.Unmarshal(decryptedSR, &sharingRecord)

	//check sr hmac
	receivedHmac,_ := userlib.HMACEval(sharingRecord.HmacKey, securedFsr[64:])
	if !userlib.HMACEqual(securedFsr[:64], receivedHmac){
		return errors.New("hmac not equal")
	}

	//retrieve filedata from datastore
	marshalledFileData,_ := userlib.DatastoreGet(sharingRecord.FileUuid)
	var fileData FileData
	json.Unmarshal(marshalledFileData, &fileData)

	encryptedMetaData := fileData.MetaData[64:]
	encryptedMetaDataHmac := fileData.MetaData[:64]

	//check if metadata is corrupted
	receivedMetaDataHmac,_ := userlib.HMACEval(sharingRecord.FileHmacKey, encryptedMetaData)
	if !userlib.HMACEqual(encryptedMetaDataHmac, receivedMetaDataHmac) {
		return errors.New("file metadata corrupted")
	}

	//decrypt encrypted metadata
	marshalledMetaData := userlib.SymDec(sharingRecord.FileSymmetricKey, encryptedMetaData)
	var metaData MetaData
	json.Unmarshal(marshalledMetaData, &metaData)

	//encrypt newly appended data
	appendedEncData := userlib.SymEnc(sharingRecord.FileSymmetricKey, userlib.RandomBytes(16), data)
	appendedHmac,_ := userlib.HMACEval(sharingRecord.FileHmacKey, appendedEncData)
	appendedSecureData := append(appendedHmac, appendedEncData...)
	fileData.Data = append(fileData.Data, appendedSecureData...)
	metaData.Appends = append(metaData.Appends, len(appendedSecureData))

	//encrypt file metadata with symmetric key
	updatedMarshalledMetaData,_ := json.Marshal(metaData)
	updatedEncMetaData := userlib.SymEnc(sharingRecord.FileSymmetricKey, userlib.RandomBytes(16), updatedMarshalledMetaData)
	updatedHmacMetaData,_ := userlib.HMACEval(sharingRecord.FileHmacKey, updatedEncMetaData)
	securedMetaData := append(updatedHmacMetaData, updatedEncMetaData...)

	//update file data
	fileData.MetaData = securedMetaData
	updatedMarshalledFileData,_ := json.Marshal(fileData)

	//store file to datastore
	userlib.DatastoreSet(sharingRecord.FileUuid, updatedMarshalledFileData)

	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {

	//retrieve file information from filename
	userFile := userdata.Files[filename]
	fsrKeyUuid := userFile.FsrKeyUuid
	fsrUuid := userFile.FsrUuid

	//retrieve encrypted fsr key
	encryptedFsrKey,_ := userlib.DatastoreGet(fsrKeyUuid)

	//decrypt encrypted fsr key
	fsrKey,_ := userlib.PKEDec(userdata.PrivateKey, encryptedFsrKey)

	//retrieve secured fsr
	securedFsr,_ := userlib.DatastoreGet(fsrUuid)

	var sharingRecord SharingRecord
	decryptedSR := userlib.SymDec(fsrKey, securedFsr[64:])
	json.Unmarshal(decryptedSR, &sharingRecord)

	//check sr hmac
	receivedHmac,_ := userlib.HMACEval(sharingRecord.HmacKey, securedFsr[64:])
	if !userlib.HMACEqual(securedFsr[:64], receivedHmac){
		return nil, errors.New("hmac not equal")
	}

	//retrieve filedata from datastore
	marshalledFileData,_ := userlib.DatastoreGet(sharingRecord.FileUuid)
	var fileData FileData
	json.Unmarshal(marshalledFileData, &fileData)

	encryptedData := fileData.Data
	encryptedMetaData := fileData.MetaData[64:]
	encryptedMetaDataHmac := fileData.MetaData[:64]

	//check if metadata is corrupted
	receivedMetaDataHmac,_ := userlib.HMACEval(sharingRecord.FileHmacKey, encryptedMetaData)
	if !userlib.HMACEqual(encryptedMetaDataHmac, receivedMetaDataHmac) {
		return nil, errors.New("file metadata corrupted")
	}

	//decrypt encrypted metadata
	marshalledMetaData := userlib.SymDec(sharingRecord.FileSymmetricKey, encryptedMetaData)
	var metaData MetaData
	json.Unmarshal(marshalledMetaData, &metaData)

	var count = 0
	var decryptedData []byte
	for i := 0; i < len(metaData.Appends); i++ {
		encryptedPortion := encryptedData[count:count+metaData.Appends[i]]

		//check if encrypted portion is corrupted
		encryptedPortionHmac := encryptedPortion[:64]
		receivedPortionHmac,_ := userlib.HMACEval(sharingRecord.FileHmacKey, encryptedPortion[64:])
		if !userlib.HMACEqual(encryptedPortionHmac, receivedPortionHmac) {
			return nil, errors.New("file metadata corrupted")
		}

		//decrypt encrypted portion
		decryptedPortion := userlib.SymDec(sharingRecord.FileSymmetricKey, encryptedPortion[64:])
		decryptedData = append(decryptedData, decryptedPortion...)

		count += metaData.Appends[i]
	}

	data = decryptedData
	return data, nil
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

	//retrieve file information from filename
	userFile := userdata.Files[filename]
	fsrKeyUuid := userFile.FsrKeyUuid
	fsrUuid := userFile.FsrUuid

	//retrieve encrypted fsr key
	encryptedFsrKey,_ := userlib.DatastoreGet(fsrKeyUuid)

	//decrypt encrypted fsr key
	fsrKey,_ := userlib.PKEDec(userdata.PrivateKey, encryptedFsrKey)

	//retrieve secured fsr
	securedFsr,_ := userlib.DatastoreGet(fsrUuid)
	var sharingRecord SharingRecord
	decryptedSR := userlib.SymDec(fsrKey, securedFsr[64:])
	json.Unmarshal(decryptedSR, &sharingRecord)

	//check sr hmac
	receivedHmac,_ := userlib.HMACEval(sharingRecord.HmacKey, securedFsr[64:])
	if !userlib.HMACEqual(securedFsr[:64], receivedHmac){
		return "", errors.New("hmac not equal")
	}

	//retrieve filedata from datastore
	marshalledFileData,_ := userlib.DatastoreGet(sharingRecord.FileUuid)
	var fileData FileData
	json.Unmarshal(marshalledFileData, &fileData)

	encryptedMetaData := fileData.MetaData[64:]
	encryptedMetaDataHmac := fileData.MetaData[:64]

	//check if metadata is corrupted
	receivedMetaDataHmac,_ := userlib.HMACEval(sharingRecord.FileHmacKey, encryptedMetaData)
	if !userlib.HMACEqual(encryptedMetaDataHmac, receivedMetaDataHmac) {
		return "", errors.New("file metadata corrupted")
	}

	//decrypt encrypted metadata
	marshalledMetaData := userlib.SymDec(sharingRecord.FileSymmetricKey, encryptedMetaData)
	var metaData MetaData
	json.Unmarshal(marshalledMetaData, &metaData)

	//generate uuid for sharing record
	srUuidSeed := userlib.Argon2Key([]byte(userdata.Username+recipient+filename),
		userlib.RandomBytes(16), 32)
	srUuid,_ := uuid.FromBytes(srUuidSeed[:16])
	newFsrKey := srUuidSeed[16:]

	//create new filesharing record
	userdata.CreateNewFileSharingRecord(srUuid, sharingRecord.FileUuid, sharingRecord.FileSymmetricKey,
		sharingRecord.FileHmacKey, newFsrKey)

	//encrypt fsr key and store to datastore
	encryptedFsrKeyUuid := uuid.New()
	userdata.CreateFSRKeyDump(recipient, newFsrKey, encryptedFsrKeyUuid)

	//update shares in file information
	var share Share
	share.Recipient = recipient
	share.Sender = userdata.Username
	share.FsrKeyUuid = encryptedFsrKeyUuid
	share.FsrUuid = srUuid
	metaData.Shares = append(metaData.Shares, share)
	updatedMarshalledMetaData,_ := json.Marshal(metaData)

	//encrypt and secure metadata
	updatedEncryptedMetaData := userlib.SymEnc(sharingRecord.FileSymmetricKey, userlib.RandomBytes(16), updatedMarshalledMetaData)
	updatedHmacMetaData,_ := userlib.HMACEval(sharingRecord.FileHmacKey, updatedEncryptedMetaData)
	updatedSecuredMetaData := append(updatedHmacMetaData, updatedEncryptedMetaData...)
	fileData.MetaData = updatedSecuredMetaData

	// store updated file
	updatedMarshalledFileData,_ := json.Marshal(fileData)

	//store file to datastore
	userlib.DatastoreSet(sharingRecord.FileUuid, updatedMarshalledFileData)

	//generate magic string (sr uiid) and sign with ds
	encryptedFsrKeyUuidByte,_ := encryptedFsrKeyUuid.MarshalBinary()
	srUuidByte,_ := srUuid.MarshalBinary()
	combined := append(encryptedFsrKeyUuidByte, srUuidByte...)
	srDigSig,_ := userlib.DSSign(userdata.SignKey, combined)
	magicByte := append(srDigSig, combined...)

	return hex.EncodeToString(magicByte), nil
}

func (userdata *User) CreateNewFileSharingRecord(srUuid uuid.UUID, fileUuid uuid.UUID,
	fileSymKey []byte, fileHmacKey []byte, fsrKey []byte) {
	//create a sharing record
	var sharingRecord SharingRecord
	sharingRecord.HmacKey = userlib.RandomBytes(16)
	sharingRecord.FileUuid = fileUuid
	sharingRecord.FileSymmetricKey = fileSymKey
	sharingRecord.FileHmacKey = fileHmacKey

	//encrypt sharing record with fsr key
	srJson,_ := json.Marshal(sharingRecord)
	encryptedFSR := userlib.SymEnc(fsrKey, userlib.RandomBytes(16), srJson)

	//add mac to encrypted sharing record
	srHmac,_ := userlib.HMACEval(sharingRecord.HmacKey, encryptedFSR)
	securedSr := append(srHmac, encryptedFSR...)

	//store sharing record to data store
	userlib.DatastoreSet(srUuid, securedSr)
}

//encrypts fsr key with recipient's public key and stores to specified location in datastore
func (userdata *User) CreateFSRKeyDump(recipient string, fsrKey []byte, targetUuid uuid.UUID) (err error){
	recipientPubKey,_ := userlib.KeystoreGet(recipient+"pke")
	encryptedFsrKey,err1 := userlib.PKEEnc(recipientPubKey, fsrKey)
	if err1 != nil {
		return err1
	}
	userlib.DatastoreSet(targetUuid, encryptedFsrKey)
	return nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {


	// verify digital signature
	senderVerify,_ := userlib.KeystoreGet(sender+"ds")
	magicByte,_ := hex.DecodeString(magic_string)
	srDigSig := magicByte[:256]
	combined := magicByte[256:]
	signatureError := userlib.DSVerify(senderVerify, combined, srDigSig)
	if signatureError != nil{
		return signatureError
	}

	//extract information from combined
	encryptedFsrKeyUuidByte := combined[:16]
	encryptedFsrKeyUuid := bytesToUUID(encryptedFsrKeyUuidByte)
	srUuidByte := combined[16:]
	srUuid := bytesToUUID(srUuidByte)

	//write file to userdata
	var userFile UserFile
	userFile.FsrUuid = srUuid
	userFile.FsrKeyUuid = encryptedFsrKeyUuid
	userdata.Files[filename] = userFile

	//encrypt userdata
	jsonUserdata,_ := json.Marshal(userdata)
	encrypted := userlib.SymEnc(userdata.SymmetricKey, userlib.RandomBytes(16), jsonUserdata)
	ciphertext := append(userdata.Salt, encrypted...)

	//hmac encrypted data
	hmac,_ := userlib.HMACEval(userdata.HmacKey, encrypted)
	securedData := append(hmac, ciphertext...)

	//store secured data to datastore
	userlib.DatastoreSet(userdata.Uuid, securedData)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {

	//retrieve file information from filename
	userFile := userdata.Files[filename]
	fsrKeyUuid := userFile.FsrKeyUuid
	fsrUuid := userFile.FsrUuid

	//retrieve encrypted fsr key
	encryptedFsrKey,_ := userlib.DatastoreGet(fsrKeyUuid)

	//decrypt encrypted fsr key
	fsrKey,_ := userlib.PKEDec(userdata.PrivateKey, encryptedFsrKey)

	//retrieve secured fsr
	securedFsr,_ := userlib.DatastoreGet(fsrUuid)
	var sharingRecord SharingRecord
	decryptedSR := userlib.SymDec(fsrKey, securedFsr[64:])
	json.Unmarshal(decryptedSR, &sharingRecord)

	//check sr hmac
	receivedHmac,_ := userlib.HMACEval(sharingRecord.HmacKey, securedFsr[64:])
	if !userlib.HMACEqual(securedFsr[:64], receivedHmac){
		return errors.New("hmac not equal")
	}

	//retrieve filedata from datastore
	marshalledFileData,_ := userlib.DatastoreGet(sharingRecord.FileUuid)
	var fileData FileData
	json.Unmarshal(marshalledFileData, &fileData)

	encryptedMetaData := fileData.MetaData[64:]
	encryptedMetaDataHmac := fileData.MetaData[:64]

	//check if metadata is corrupted
	receivedMetaDataHmac,_ := userlib.HMACEval(sharingRecord.FileHmacKey, encryptedMetaData)
	if !userlib.HMACEqual(encryptedMetaDataHmac, receivedMetaDataHmac) {
		return errors.New("file metadata corrupted")
	}

	//decrypt encrypted metadata
	marshalledMetaData := userlib.SymDec(sharingRecord.FileSymmetricKey, encryptedMetaData)
	var metaData MetaData
	json.Unmarshal(marshalledMetaData, &metaData)

	//decrypt filedata for re encryption
	var count = 0
	var decryptedData []byte
	encryptedData := fileData.Data
	for i := 0; i < len(metaData.Appends); i++ {
		encryptedPortion := encryptedData[count:count+metaData.Appends[i]]

		//check if encrypted portion is corrupted
		encryptedPortionHmac := encryptedPortion[:64]
		receivedPortionHmac,_ := userlib.HMACEval(sharingRecord.FileHmacKey, encryptedPortion[64:])
		if !userlib.HMACEqual(encryptedPortionHmac, receivedPortionHmac) {
			return errors.New("file data corrupted")
		}

		//decrypt encrypted portion
		decryptedPortion := userlib.SymDec(sharingRecord.FileSymmetricKey, encryptedPortion[64:])
		decryptedData = append(decryptedData, decryptedPortion...)

		count += metaData.Appends[i]
	}

	//create new keys to encrypt file
	keyString,_ := userlib.HMACEval(userlib.RandomBytes(16), sharingRecord.FileSymmetricKey)
	newSymmetricKey := keyString[:16]
	newHmacKey := keyString[16:32]

	//encrypt file data again
	newEncryptedData := userlib.SymEnc(newSymmetricKey, userlib.RandomBytes(16), decryptedData)
	newHmacData,_ := userlib.HMACEval(newHmacKey, newEncryptedData)
	newSecuredData := append(newHmacData, newEncryptedData...)
	fileData.Data = newSecuredData

	//update shares in file information
	var shares []Share
	for i := 0; i < len(metaData.Shares); i++ {
		if metaData.Shares[i].Sender != target_username && metaData.Shares[i].Recipient != target_username {
			shares = append(shares, metaData.Shares[i])
		}
	}
	metaData.Shares = shares
	var newAppends []int
	newAppends = append(newAppends, len(newSecuredData))
	metaData.Appends = newAppends

	//encrypt and secure metadata
	updatedMarshalledMetaData,_ := json.Marshal(metaData)
	updatedEncryptedMetaData := userlib.SymEnc(newSymmetricKey, userlib.RandomBytes(16), updatedMarshalledMetaData)
	updatedHmacMetaData,_ := userlib.HMACEval(newHmacKey, updatedEncryptedMetaData)
	updatedSecuredMetaData := append(updatedHmacMetaData, updatedEncryptedMetaData...)
	fileData.MetaData = updatedSecuredMetaData

	// store updated file
	updatedMarshalledFileData,_ := json.Marshal(fileData)

	//store file to datastore
	userlib.DatastoreSet(sharingRecord.FileUuid, updatedMarshalledFileData)

	//update relevant fsrs
	for i := 0; i < len(shares); i++ {
		share := shares[i]
		//generate uuid for sharing record
		srUuidSeed,_ := userlib.HMACEval(userlib.RandomBytes(16), fsrKey)
		newFsrKey := srUuidSeed[:16]
		userdata.CreateNewFileSharingRecord(share.FsrUuid, sharingRecord.FileUuid, newSymmetricKey, newHmacKey, newFsrKey)
		userdata.CreateFSRKeyDump(share.Recipient, newFsrKey, share.FsrKeyUuid)
	}
	return
}
