package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	// Tests if the user is initialized correctly
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}

	u, err = InitUser("alice", "fubar2")
	if err == nil {
		// t.Error says the test fails
		t.Error("Should have failed to initialize user", err)
	}

	// Tests if the username is not empty (error on success)
	u, err = InitUser("","fubar")
  	if err == nil {
    	t.Error("Failed blank username input")
	}

	// Tests if password is not empty (error on success)
	u, err = InitUser("anand","")
  	if err == nil {
    	t.Error("Failed blank password input")
	}

	// Tests if same username was used previously (error on success)
	u, err = InitUser("alice","fub")
	if err == nil {
		// t.Error says the test fails
		t.Error("Failed to have a unique username initialized", err)
	}

	// Tests if concatenated version of username + password is a user
	u, err = InitUser("alicefubar", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}

	// t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	// Test if incorrect password returns an error
	u, err = GetUser("alice", "wrong")
	if err == nil {
		t.Error("Incorrect password")
	}

	// Test if get user with correct password returns the same one as we initialize
	u, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user",err)
	}

	// Test if unintialized user is loaded
	_ , err = GetUser("anand","fubar")
	if err == nil {
		t.Error("Reload unitialized user")
	}

	_ = u
}

func TestStorage(t *testing.T) {
	clear()

	// Tests if the user is initialized correctly and file loads correctly
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	// Tests if the downloaded file is the same as the uploaded file
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}

	// Tests if the user tried to store a file with a filename previously used
	v3 := []byte("Same filename with different content")
	u.StoreFile("file1", v3)

	v7, err3 := u.LoadFile("file1")
	if !reflect.DeepEqual(v7, v) {
		t.Error("Filename already in use for this user", err3)
		return
	}

	// Tests if a different user has the same filename
	u2, err := InitUser("vik", "anand")
	if err != nil {
		t.Error("Failed to initialize user")
	}

	v5 := []byte("Same filename but different user")

	u2.StoreFile("file1", v5)

	v6, err4 := u2.LoadFile("file1")
	if err4 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}

	// Tests if the downloaded file is the same as the uploaded file
	if !reflect.DeepEqual(v5, v6) {
		t.Error("Downloaded file is not the same", v5, v6)
		return
	}

	// Tests if a file that has not been stored is loaded
	_, err = u.LoadFile("file0")
	if err == nil {
		t.Error("An invalid file has been loaded")
	}

	// Tests if the same file content was stored in different filenames
	u.StoreFile("file11", v)
	v8, err := u.LoadFile("file11")
	if err != nil {
		t.Error("Failed to upload and download", err)
	}
	if !reflect.DeepEqual(v, v8) {
		t.Error("Failed to store same content under a different filename")
	}
}

func TestAppend(t *testing.T) {
	clear()
	// Tests if a user is initialized correctly and if a file is appended correctly
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	// t.Log("Loaded user", u.Username)

	v := []byte("This is a test.")
	u.StoreFile("file1", v)

	v2 := []byte("Appending to file")
	err = u.AppendFile("file1", v2)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}

	v3, _ := u.LoadFile("file1")
	if !reflect.DeepEqual(v3, append(v, v2...)) {
		t.Error("Failed to append")
	}

	// Tests if multiple appends on the same file works
	v4 := []byte("Another append")
	err = u.AppendFile("file1", v4)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}

	// Appending file that does not exist
	// Check if file loads properly
	// Check if files appended is not same as original
}

func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	u3, err3 := InitUser("charlie", "foohbar")
	if err3 != nil {
		t.Error("Failed to initialize charlie", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	var v2, v4, v5 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	// Tests if alice can properly share a file with one user (bob)
	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u2.ReceiveFile("file1-bob", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file1-bob")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	v3 := []byte("Appending to file")
	err = u2.AppendFile("file1-bob", v3)
	if err != nil {
		t.Error("Failed to append file", err)
		return
	}

	// Tests if alice can properly share a file with two users (bob + charlie)
	magic_string, err = u.ShareFile("file1", "charlie")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u3.ReceiveFile("file1-charlie", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v4, err = u3.LoadFile("file1-charlie")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	v5, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download owner's file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v4, v5) {
		t.Error("Shared file is not the same", v, v4)
		return
	}
}

func TestRevoke(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	var v2 []byte
	u.StoreFile("file1", v)
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}

	err = u2.ReceiveFile("file-bob", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the file", err)
	}

	// Tests if the function RevokeFile compiles properly
	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke the file", err)
	}

	// Tests if Alice is still able to download the revoked file
	v2, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the revoked file", err)
	}

	// Tests if Bob is still able to update the file after Alice revokes
	err = u2.AppendFile("rainy day", v)
	if err == nil {
		t.Error("Failed to remove append permissions from Bob")
		return
	}

	// Tests if Bob no longer has access to the revoked file
	_, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Failed to revoke the file properly since Bob still has access")
	}

	// Tests if the revoked file is the same as the original file
	if !reflect.DeepEqual(v, v2) {
		t.Error("Failed to verify that the revoked file is the same", v, v2)
	}
}
//
// func Test1(t *testing.T) {
// 	clear()
// 	// Tests if the user is initialized correctly
// 	u, err := InitUser("alice", "fubar")
// 	if err != nil {
// 		// t.Error says the test fails
// 		t.Error("Failed to initialize user", err)
// 	}
//
// 	u2, err2 := InitUser("bob", "bobar")
// 	if err2 != nil {
// 		// t.Error says the test fails
// 		t.Error("Failed to initialize user", err)
// 	}
//
// 	// Tests if another user is initialized with a username in use
// 	u3, err3 := InitUser("alice", "foobar")
// 	if err3 == nil {
// 		t.Error("Initialized user with a username in use", err)
// 	}
//
// 	// Tests if GetUser works on alice with bob's password
// 	u, err = GetUser("alice", "foobar")
// 	if err == nil {
// 		t.Error("Get alice should not work with bob's password",err)
// 	}
//
// 	// userDS, err3 := userlib.HashKDF(UUIDtoBytes(uuid)[:16], []byte("user struct"))
// 	// userlib.DatastoreSet(BytesToUUID(userDS), []byte("alskdfjlaksdjflaksdjf"))
//
// 	// t.Log("Got user", u)
// 	// t.Log("Got user", u2)
// 	// t.Log("Got user", u3)
// }
