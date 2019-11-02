package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"encoding/hex"
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
)


func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)
	// someUsefulThings()  //  Don't call someUsefulThings() in the autograder in case a student removes it
	userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("Loaded user", u)

	v := []byte("This is a test")
	t.Log("starting to store file")
	u.StoreFile("file1", v)
	t.Log("file store complete")


	t.Log("starting to loaf file")
	v2, err2 := u.LoadFile("file1")
	t.Log("file load complete")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}

func TestShare(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestUser_RevokeFile(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	var v, v2, v3 []byte

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	u2, err := GetUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file from bob", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is initially not the same", v, v2)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Failed to revoke file", err)
		return
	}

	v3, err = u2.LoadFile("file2")
	t.Log("alice's file is: " + hex.EncodeToString(v))
	t.Log("bob's file is: " + hex.EncodeToString(v2))
	t.Log("bob's file after revocation: " + hex.EncodeToString(v3))
	if err == nil {
		t.Error("Can still download the file from bob", err)
		return
	}
	if reflect.DeepEqual(v, v3) {
		t.Error("Shared file is still the same", v, v3)
		return
	}


}
