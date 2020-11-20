package proj2

// CS 161 Project 2 Fall 2020
// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder. We will be very upset.

import (
	// You neet to add with
	// go get github.com/cs161-staff/userlib
	"github.com/cs161-staff/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging, etc...
	"encoding/hex"

	// UUIDs are generated right based on the cryptographic PRNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	"strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
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
func BytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	Password string
	UUID uuid.UUID
	PrivateKey userlib.PKEDecKey
	PublicKey userlib.PKEEncKey
	DSPrivateKey userlib.DSSignKey
	DSPublicKey userlib.DSVerifyKey
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

type FileStore struct {
	PublicKey userlib.PKEEncKey
	PrivateKey userlib.PKEDecKey
	DSPrivateKey userlib.DSSignKey
	DSPublicKey userlib.DSVerifyKey
	NumPieces int
}

type Received struct {
	FUID []byte
	SUID []byte
	Signature []byte
}

// Helper function: creates UserPass as defined in design doc
func UserPass(username string, password string) (userpass []byte) {
	// return "user:" + userlib.Hash([]byte(username)) + "pass:" + userlib.Hash([]byte(password))
	hashed64 := userlib.Hash([]byte("user:" + username + "pass:" + password))
	return hashed64[:16]
}

// Helper function: converts UUID type to byte representation
func UUIDtoBytes(uuid uuid.UUID) (bytes []byte) {
	return []byte(uuid.String())
}

// Helper function: converts string to 16-byte key
func StringToKey(data string) (bytes []byte) {
	bytes = []byte(data)
	padding := make([]byte, 16, 16)
	if len(bytes) < 16 {
		bytes = append(bytes, padding...)
	}
	return bytes[:16]
}

// Helper function: pad to multiple of 16 for encryption
func PadForEncryption(data []byte) (paddedData []byte) {
	overlap := len(data) % 16
	padLength := 16 - overlap
	padding := make([]byte, padLength, padLength)
	for i := 0; i < padLength; i++ {
		padding[i] = byte(padLength)
	}
	return append(data, padding...)
}

func DecryptData(key []byte, ciphertext []byte) (bytes []byte, err error) {
	if key == nil || ciphertext == nil { return nil, errors.New(strings.ToTitle("Decrypt data")) }
	decrypted := userlib.SymDec(key, ciphertext)
	// need to remove padding
	// take last element (= padLength)
	// use a for loop to verify that there are padLength values of padLength at the end
	padLength := int(decrypted[len(decrypted) - 1])
	for i := 0; i < padLength; i++ {
		if int(decrypted[len(decrypted) - 1 - i]) != padLength {
			return decrypted, nil
		}
	}
	return decrypted[:len(decrypted) - padLength], nil
}

func FetchFUID(userdata User, filename string) (FUID []byte, err error) {
	fileText := "file: " + filename
	possibleFUID, possibleFUIDErr := FetchFromDS(UUIDtoBytes(userdata.UUID), fileText)
	if possibleFUIDErr != nil { return nil, possibleFUIDErr }
	macErr := VerifyMac(UUIDtoBytes(userdata.UUID), fileText, possibleFUID)
	if macErr != nil { return nil, macErr }
	_, isFUID := FetchFromDS(possibleFUID, "file data")

	if isFUID == nil {
		FUID = possibleFUID
	} else {
		sharedHandle := possibleFUID
		FUID, _ = FetchFromDS(sharedHandle, "file")
	}
	if FUID == nil { return nil, errors.New(strings.ToTitle("Error fetching FUID")) }
	return FUID, nil
}

func WriteToDS(locKey []byte, loc string, data []byte, key userlib.DSSignKey) (err error) {
	if len(locKey) < 16 { return errors.New(strings.ToTitle("Invalid key writing at location " + loc)) }
	dataLoc, err := userlib.HashKDF(locKey[:16], []byte(loc))
	dataEnc := userlib.SymEnc(locKey[:16], userlib.RandomBytes(16), PadForEncryption(data))
	if err != nil { return err }
	userlib.DatastoreSet(BytesToUUID(dataLoc), dataEnc)
	errds := WriteDigitalSignature(key, data, locKey, loc)
	errmac := WriteMac(data, locKey, loc)
	if errds != nil { return errds }
	if errmac != nil { return errmac }
	return
}

func WriteDigitalSignature(key userlib.DSSignKey, data []byte, locKey []byte, loc string) (err error) {
	dsigData, err1 := userlib.DSSign(key, data) // dsig for data
	dsigLoc, err2 := userlib.HashKDF(locKey[:16], []byte(loc + " ds"))
	if err1 != nil { return err1 }
	if err2 != nil { return err2 }
	userlib.DatastoreSet(BytesToUUID(dsigLoc), dsigData)
	return
}

func WriteMac(data []byte, locKey []byte, loc string) (err error) {
	macKey, err := userlib.HashKDF(locKey[:16], []byte(loc + " mac enc"))
	macData, err1 := userlib.HMACEval(macKey[:16], data)
	macLoc, err2 := userlib.HashKDF(locKey[:16], []byte(loc + " mac"))
	if err != nil { return err }
	if err1 != nil { return err1 }
	if err2 != nil { return err2 }
	userlib.DatastoreSet(BytesToUUID(macLoc), macData)
	return
}

func FetchAndVerify(locKey []byte, loc string, publicKey userlib.DSVerifyKey) (data []byte, err error) {
	data, err = FetchFromDS(locKey, loc)

	digitalSigErr := VerifyDigitalSignature(locKey, loc, data, publicKey)
	if digitalSigErr != nil { return nil, digitalSigErr }
	macErr := VerifyMac(locKey, loc, data)
	if macErr != nil { return nil, macErr }
	return data, nil
}

func FetchFromDS(locKey []byte, loc string) (data []byte, err error) {
	if len(locKey) < 16 { return nil, errors.New(strings.ToTitle("Invalid key fetching at location " + loc)) }
	dataLoc, err := userlib.HashKDF(locKey[:16], []byte(loc))
	if err != nil { return nil, err }
	dataEnc, _ := userlib.DatastoreGet(BytesToUUID(dataLoc))
	if dataEnc == nil { return nil, errors.New(strings.ToTitle("No data at location " + loc)) }
	data, err = DecryptData(locKey[:16], dataEnc)
	return data, err
}

// Helper function to verify digital sig
// Notes: data is decrypted
func VerifyDigitalSignature(locKey []byte, loc string, data []byte, key userlib.DSVerifyKey) (err error) {
	dsigLoc, err := userlib.HashKDF(locKey[:16], []byte(loc + " ds"))
	if err != nil { return err }
	dsigData, _ := userlib.DatastoreGet(BytesToUUID(dsigLoc))
	if dsigData == nil { return errors.New(strings.ToTitle("No signature for location: " + loc)) }
	signErr := userlib.DSVerify(key, data, dsigData)
	if signErr != nil { return errors.New(strings.ToTitle("Invalid signature for location: " + loc)) }
	return
}

// Helper function to verify mac
// Notes: data is decrypted
func VerifyMac(locKey []byte, loc string, data []byte) (err error) {
	macLoc, err := userlib.HashKDF(locKey[:16], []byte(loc + " mac"))
	if err != nil { return err }
	originalMac, _ := userlib.DatastoreGet(BytesToUUID(macLoc))
	macKey, _ := userlib.HashKDF(locKey[:16], []byte(loc + " mac enc"))
	if originalMac == nil || macKey == nil { return errors.New(strings.ToTitle("No mac for location: " + loc)) }
	newMac, _ := userlib.HMACEval(macKey[:16], data)
	macValidated := userlib.HMACEqual(newMac, originalMac)
	if !macValidated { return errors.New(strings.ToTitle("Invalid mac for location: " + loc)) }
	return
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the password has strong entropy, EXCEPT
// the attackers may possess a precomputed tables containing
// hashes of common passwords downloaded from the internet.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	if username == "" || password == "" {
		return nil, errors.New(strings.ToTitle("Invalid credentials"))
	}

	// 1. Check if user exists
	_, userExists := userlib.KeystoreGet(username + "rsa")
	if userExists { return nil, errors.New(strings.ToTitle("User already exists")) }

	// 2. User doesn't exist. Create UUID, RSA Keys, populate User struct
	uuid := uuid.New()
	pk, sk, _ := userlib.PKEKeyGen()
	dssk, dspk, _ := userlib.DSKeyGen()
	userdata.Username = username
	userdata.Password = password
	userdata.UUID = uuid
	userdata.PublicKey = pk
	userdata.PrivateKey = sk
	userdata.DSPublicKey = dspk
	userdata.DSPrivateKey = dssk

	// 3. Update user info in KeyStore and DataStore (see design doc)
	userPass := UserPass(username, password)
	jsonUserdata, _ := json.Marshal(userdata)

	// Keystore
	userlib.KeystoreSet(username + "rsa", pk) // public key
	userlib.KeystoreSet(username + "ds", dspk) // public key

	// Data
	err = WriteToDS(userPass, "uuid", UUIDtoBytes(uuid), userdata.DSPrivateKey)
	if err != nil { return nil, err }
	err = WriteToDS(UUIDtoBytes(userdata.UUID), "user struct", jsonUserdata, userdata.DSPrivateKey)
	if err != nil { return nil, err }

	_ = userlib.Argon2Key([]byte(password), []byte(username), 16) // Slow down function

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// 1. Verify user exists in database
	_, userExists := userlib.KeystoreGet(username + "rsa")
	if !userExists { return nil, errors.New(strings.ToTitle("User does not exist")) }

	dsKey, ok := userlib.KeystoreGet(username + "ds")
	if !ok { return nil, errors.New(strings.ToTitle("Invalid ds key at location getting user")) }

	userPass := UserPass(username, password)
	uuid, uuidErr := FetchAndVerify(userPass, "uuid", dsKey)
	if uuidErr != nil { return nil, uuidErr }

	decUser, decUserErr := FetchAndVerify(uuid, "user struct", dsKey)
	if decUserErr != nil { return nil, decUserErr }
	json.Unmarshal(decUser, &userdataptr)

	// 3. Use UUID to verify password
	// uuidPass, _ := userlib.HashKDF(uuid, []byte("password"))
	// hashedPass := userlib.Argon2Key(password, username, 16)
	// if uuidPass == nil { return nil, errors.New(strings.ToTitle("Invalid login")) }
	// storedPass := userlib.KeystoreGet(uuidPass)
	// if storedPass != hashedPass { return nil, errors.New(strings.ToTitle("Invalid login")) }

	_ = userlib.Argon2Key([]byte(password), []byte(username), 16) // Slow down function

	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The plaintext of the filename + the plaintext and length of the filename
// should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	// 1. Check if file exists ADDRESS
	fileText := "file: " + filename
	fileLocDS, _ := userlib.HashKDF(UUIDtoBytes(userdata.UUID)[:16], []byte(fileText))
	if fileLocDS == nil { return }
	_, fileExists := userlib.DatastoreGet(BytesToUUID(fileLocDS))
	if fileExists { return }

	// 2. Generate FUID and keys
	FUID := uuid.New()
	pk, sk, _ := userlib.PKEKeyGen()
	dssk, dspk, _ := userlib.DSKeyGen()

	// 3. Write data
	var filedata FileStore
	filedata.PublicKey = pk
	filedata.PrivateKey = sk
	filedata.NumPieces = 1
	filedata.DSPublicKey = dspk
	filedata.DSPrivateKey = dssk
	packagedFiledata, _ := json.Marshal(filedata)

	// Write FUID
	fuidErr := WriteToDS(UUIDtoBytes(userdata.UUID), fileText, UUIDtoBytes(FUID), filedata.DSPrivateKey)
	if fuidErr != nil { return }

	// Write file data
	fileDataErr := WriteToDS(UUIDtoBytes(FUID), "file data", packagedFiledata, filedata.DSPrivateKey)
	if fileDataErr != nil { return }

	// Write file content
	filePartText := "part " + strconv.Itoa(0)
	filePartErr := WriteToDS(UUIDtoBytes(FUID), filePartText, data, filedata.DSPrivateKey)
	if filePartErr != nil { return }

	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var filestore FileStore

	// 1. Verify file exists for user
	FUID, err := FetchFUID(*userdata, filename)
	if FUID == nil { return err }

	// 2. Fetch FileStore object
	filedata, filedataErr := FetchFromDS(FUID, "file data")
	if filedataErr != nil { return filedataErr }
	json.Unmarshal(filedata, &filestore)
	// verify mac and sig
	macErr := VerifyMac(FUID, "file data", filedata)
	if macErr != nil { return macErr }
	sigErr := VerifyDigitalSignature(FUID, "file data", filedata, filestore.DSPublicKey)
	if sigErr != nil { return sigErr }
	filestore.NumPieces = filestore.NumPieces + 1
	packagedFiledata, _ := json.Marshal(filestore)
	WriteToDS(FUID, "file data", packagedFiledata, filestore.DSPrivateKey)

	filePartText := "part " + strconv.Itoa(filestore.NumPieces - 1)
	filePartErr := WriteToDS(FUID, filePartText, data, filestore.DSPrivateKey)
	if filePartErr != nil { return filePartErr }

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	var filestore FileStore

	// 1. Fetch file FUID
	FUID, err := FetchFUID(*userdata, filename)
	if FUID == nil { return nil, err }

	// 2. Fetch FileStore object
	filedata, filedataErr := FetchFromDS(FUID, "file data")
	if filedataErr != nil { return nil, filedataErr }
	json.Unmarshal(filedata, &filestore)
	// verify mac and sig
	macErr := VerifyMac(FUID, "file data", filedata)
	if macErr != nil { return nil, macErr }
	sigErr := VerifyDigitalSignature(FUID, "file data", filedata, filestore.DSPublicKey)
	if sigErr != nil { return nil, sigErr }

	var fileBytes []byte
	for i := 0; i < filestore.NumPieces; i++ {
		filePartText := "part " + strconv.Itoa(i)
		filePartData, filePartErr := FetchAndVerify(FUID, filePartText, filestore.DSPublicKey)
		if filePartErr != nil { return nil, filePartErr }
		fileBytes = append(fileBytes, filePartData...)
	}

	return fileBytes, nil
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

	// 1. Fetch file FUID
	FUID, err := FetchFUID(*userdata, filename)
	if FUID == nil { return "", err }

	// 2. Generate recipient key and share
	var sharedData map[string][]byte
	SUID := uuid.New()
	sharedLoc := string(append([]byte("shared: "), FUID[:16]...))
	fetchedSharedData, fetchedSharedDataErr := FetchFromDS(UUIDtoBytes(userdata.UUID), sharedLoc)
	if fetchedSharedData == nil || fetchedSharedDataErr != nil {
		sharedData = make(map[string][]byte)
	} else {
		json.Unmarshal(fetchedSharedData, &sharedData)
	}

	sharedData[recipient] = UUIDtoBytes(SUID)
	sharedDataJson, _ := json.Marshal(sharedData)
	WriteToDS(UUIDtoBytes(userdata.UUID), sharedLoc, sharedDataJson, userdata.DSPrivateKey)

	var receivedStruct Received
	receivedStruct.FUID = FUID
	receivedStruct.SUID = UUIDtoBytes(SUID)
	signature, err := userlib.DSSign(userdata.DSPrivateKey, UUIDtoBytes(SUID))
	if err != nil { return "", errors.New(strings.ToTitle("Signature error")) }
	receivedStruct.Signature = signature
	receivedData, _ := json.Marshal(receivedStruct)

	return string(receivedData), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	var receivedStruct Received
	json.Unmarshal([]byte(magic_string), &receivedStruct)

	// 1. Fetch sender's DS public key
	senderDSPK, _ := userlib.KeystoreGet(sender + "ds")

	// 2. Verify signature
	err := userlib.DSVerify(senderDSPK, receivedStruct.SUID, receivedStruct.Signature)
	if err != nil { return errors.New(strings.ToTitle("Invalid signature")) }

	// 3. Write to Datastore
	fileText := "file: " + filename
	WriteToDS(receivedStruct.SUID, "user", UUIDtoBytes(userdata.UUID), userdata.DSPrivateKey)
	WriteToDS(receivedStruct.SUID, "file", receivedStruct.FUID, userdata.DSPrivateKey)
	WriteToDS(UUIDtoBytes(userdata.UUID), fileText, receivedStruct.SUID, userdata.DSPrivateKey)

	return nil
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	// 1. Fetch FUID
	FUID, err := FetchFUID(*userdata, filename)
	if FUID == nil { return err }

	// 2. Fetch share tree and retrieve SUID
	sharedData := FetchShareData(UUIDtoBytes(userdata.UUID), FUID)
	SUID := sharedData[string(target_username)]
	if SUID == nil { return errors.New(strings.ToTitle("No shared file")) }

	// 3. Remove access from SUID, and fetch target UUID
	UUID, err := RevokeFileHelper(SUID)
	if err != nil { return err }

	// 4. Fetch target share tree and recursively revoke
	RevokeAccessRecurse(UUID, FUID)
	return
}

func RevokeFileHelper(SUID []byte) (UUID []byte, err error) {
	uuidHandle, _ := userlib.HashKDF(SUID[:16], []byte("user"))
	fileHandle, _ := userlib.HashKDF(SUID[:16], []byte("file"))
	uuidEnc, _ := userlib.DatastoreGet(BytesToUUID(uuidHandle))
	if uuidEnc == nil { return nil, errors.New(strings.ToTitle("No UUID found")) }
	userlib.DatastoreDelete(BytesToUUID(fileHandle))
	UUID, _ = DecryptData(SUID[:16], uuidEnc)
	return UUID, nil
}

func FetchShareData(UUID []byte, FUID []byte) (map[string][]byte) {
	var sharedData map[string][]byte
	sharedDS, _ := userlib.HashKDF(UUID[:16], append([]byte("shared: "), FUID[:16]...))
	userlib.DatastoreGet(BytesToUUID(sharedDS))
	sharedDataEnc, _ := userlib.DatastoreGet(BytesToUUID(sharedDS))
	if sharedDataEnc == nil {
		sharedData = make(map[string][]byte)
	} else {
		readSharedData, _ := DecryptData(UUID[:16], sharedDataEnc)
		json.Unmarshal(readSharedData, &sharedData)
	}
	return sharedData
}

func RevokeAccessRecurse(UUID []byte, FUID []byte) (err error) {
	// 1. Fetch share tree for user
	sharedData := FetchShareData(UUID, FUID)

	// 2. For each: find SUID, revoke, fetch UUID, and recurse
	for _, SUID := range sharedData {
		if SUID == nil { continue }
		UUID, err := RevokeFileHelper(SUID)
		if err != nil { continue }
		RevokeAccessRecurse(UUID, FUID)
	}

	return
}
