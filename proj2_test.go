package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/nweaver/cs161-p2/userlib"
	_ "encoding/json"
	"encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	 "errors"
)


func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	 userlib.SetDebugStatus(false)
	 someUsefulThings()
	 userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
	v, err := GetUser("alice", "fubar")

	if err != nil {
		t.Error("Failed to Get User,", err)
	}

	if !reflect.DeepEqual(u, v) {
		t.Error("Recieved User different from Initialzed User, ", v, u)
	}

}

func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("\n\nLoaded user", u)

	v := []byte("This is a test")
	u.StoreFile("file1", v)


	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestLoadFail(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("\n\nLoaded user", u)

	v := []byte("This is a file with file name: filename.txt")
	u.StoreFile("filename.txt", v)

	t.Log("\n\nStored file filename.txt, ", u)

	v2, err2 := u.LoadFile("filename2")

	if err2 == nil {
		t.Error("File name of filename2 shouldn't exist")
	}

	if v2 != nil {
		t.Error("File shouldnt exist, but received: ", v2)
	}

}

func TestLoadSameFilename(t *testing.T) {
	// And some more tests, because
	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("\n\nLoaded user", alice)

	file := []byte("This is a file with file name: samefilename")
	alice.StoreFile("samefilename", file)

	t.Log("\n\nStored file samefilename, ",file)

	johndoe, err := InitUser("johndoe", "guess!my!password!")
	if err != nil {
		t.Error("Failed to reload user, ", err)
		return
	}
	t.Log("Initialized user, ", johndoe)

	johndoe, err = GetUser("johndoe", "guess!my!password!")
	t.Log("\n\nLoaded user", johndoe)

	file2 := []byte("This is a different file with file name: samefilename")
	johndoe.StoreFile("samefilename", file2)

	t.Log("\n\nStored file samefilename, ", file2)

	aliceFile, err := alice.LoadFile("samefilename")

	if err != nil {
		t.Error("Failed to load alice's file")
		return
	}

	johndoeFile, err := johndoe.LoadFile("samefilename")

	if err != nil {
		t.Error("Failed to load johndoe file")
		return
	}

	if reflect.DeepEqual(aliceFile, johndoeFile) {
		t.Error("Two files shouldn't be equal, ", aliceFile, johndoeFile)
		return
	}

}

func TestAppend(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	t.Log("\n\nLoaded user", u)

	append_version_1 := []byte("append version 1")
	append_version_2 := []byte("append version 2")
	append_version_3 := []byte("append version 3")
	append_version_4 := []byte("more append test")
	append_version_5 := []byte("dummy text.")

	u.StoreFile("append", append_version_1)

	err_1 := u.AppendFile("append", append_version_2)
	err_2 := u.AppendFile("append", append_version_3)
	err_3 := u.AppendFile("append", append_version_4)
	err_4 := u.AppendFile("append", append_version_5)

	for _, err := range []error{err_1, err_2, err_3, err_4} {
		if err != nil {
			t.Error("Failed to append file", err)
			return
		}
	}

	t.Log("\n\nFile Appended.")
	t.Log("\n\nLoaded user", u)
	file_actual, err := u.LoadFile("append")
	if err != nil {
		t.Error("Failed to reload file", err)
		return
	}

	file_expected := append(append_version_1, append_version_2...)
	file_expected = append(file_expected, append_version_3...)
	file_expected = append(file_expected, append_version_4...)
	file_expected = append(file_expected, append_version_5...)

	if !reflect.DeepEqual(file_actual, file_expected) {
		t.Error("Append File Test Failed.", file_actual, file_expected)
		return
	}
	t.Log("Append Succcess")
}

func TestAppendFail(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	toAppend := []byte("append version")

	t.Log("\n\nLoading Non existing file...")
	err = u.AppendFile("doesnotexist", toAppend)

	if err == nil {
		t.Error("Attempting to append to a nonexisting file should fail")
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
		t.Error("Failed to share the a file, ", err)
		return
	}

	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message, ", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing, ", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same, ", v, v2)
		return
	}

}

func TestShareAppend(t *testing.T) {
	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	bob, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user, ", err2)
		return
	}

	var magic_string string

	originalFile := []byte("original content")
	appendFile_1 := []byte("append version 1")
	appendFile_2 := []byte("append version 2")

	alice.StoreFile("original_file", originalFile)

	magic_string, err = alice.ShareFile("original_file", "bob")

	if err != nil {
		t.Error("Failed to share the a file, ", err)
		return
	}

	err = bob.ReceiveFile("shared_from_alice", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message, ", err)
		return
	}

	err = alice.AppendFile("original_file", appendFile_1)
	if err != nil {
		t.Error("Failed to append file, ", err)
		return
	}

	aliceFile, err := alice.LoadFile("original_file")
	if err != nil {
		t.Error("Failed to download the file after sharing, ", err)
		return
	}

	bobFile, err := bob.LoadFile("shared_from_alice")
	if err != nil {
		t.Error("Failed to download the file after sharing, ", err)
		return
	}

	if !reflect.DeepEqual(aliceFile, bobFile) {
		t.Error("Shared file after append are not the same, ", aliceFile, bobFile)
		return
	}
	err = bob.AppendFile("shared_from_alice", appendFile_2)
	if err != nil {
		t.Error("Failed to append file, ", err)
		return
	}

	aliceFile, err = alice.LoadFile("original_file")
	if err != nil {
		t.Error("Failed to download the file after sharing, ", err)
		return
	}
	bobFile, err = bob.LoadFile("shared_from_alice")
	if err != nil {
		t.Error("Failed to download the file after sharing, ", err)
		return
	}

	if !reflect.DeepEqual(aliceFile, bobFile) {
		t.Error("Shared file after append are not the same, ", aliceFile, bobFile)
		return
	}

}

func TestRevoke(t *testing.T) {
	alice, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user, ", err)
		return
	}

	bob, err2 := GetUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to reload user, ", err2)
		return
	}

	err = alice.RevokeFile("original_file")
	if err != nil {
		t.Error("Failed to revoke access for a file, ", err)
		return
	}

	aliceFile, err := alice.LoadFile("original_file")
	if err != nil {
		t.Error("Failed to download the file after revoking, ", err)
		return
	}

	bobFile, err := bob.LoadFile("shared_from_alice")
	if err == nil {
		t.Error("shared_from_alice file have been revoked, but accessed from Bob, ", err)
		return
	}

	if reflect.DeepEqual(aliceFile, bobFile) {
		t.Error("File access has been revoked, but received original content")
		return
	}
}

func TestUserIntegrity(t *testing.T) {
	user1, err := InitUser("Integrity Test", "Integrity Test Password")
	if err != nil {
		t.Error("InitUser Failed, ", err)
		return
	}

	userUUID, err := user1.GetUserUUID()
	if err != nil {
		t.Error("GetUserUUID Failed, ", err)
		return
	}

 	userCipher, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		t.Error("DatastoreGet Failed")
		return
	}

	userCipher[5] = 4

	userlib.DatastoreSet(userUUID, userCipher)

	user1, actual_err := GetUser("Integrity Test", "Integrity Test Password")
	expected_err := errors.New("Integrity Failed")
	if !reflect.DeepEqual(actual_err, expected_err) {
		t.Error("User Integrity Test Failed, ", err)
		return
	}

}

func TestFileIntegrity(t *testing.T) {
	user1, err := InitUser("File Integrity Test User", "FIle Integrity Test Password")
	if err != nil {
		t.Error("InitUser Failed, ", err)
		return
	}

	user1.StoreFile("testFilename", []byte("This is file."))
	sharingPtr, err := user1.GetSharingRecord("testFilename")
	FileUUID := sharingPtr.FileDataUUID[0]

	fileDataCipher, ok := userlib.DatastoreGet(FileUUID)
	if !ok {
		t.Error("Store File Failed")
		return
	}

	true_byte := fileDataCipher[12]
	fileDataCipher[12] = 3

	userlib.DatastoreSet(FileUUID, fileDataCipher)

	fileData, actual_err := user1.LoadFile("testFilename")

	expected_err := errors.New("Integrity Failed")
	if !reflect.DeepEqual(err, expected_err) && fileData != nil {
		t.Error("User Integrity Test Failed, ", err)
		return
	}

	fileDataCipher[12] = true_byte
	userlib.DatastoreSet(FileUUID, fileDataCipher)
	actual_fileData, actual_err := user1.LoadFile("testFilename")
	if actual_err != nil {
		t.Error("\nLoadFile Failed", err)
		return
	}

	expected_fileData := []byte("This is file.")
	if !reflect.DeepEqual(actual_fileData, expected_fileData) {
		t.Error("File should match.")
		return
	}

}
func TestFileSharingWithMITM(t *testing.T) {
	alice, err:= InitUser("ALICE", "ALICEPASSWORD")
	bob, err2 := InitUser("BOB", "BOBPASSWORD")
	if err != nil && err2 != nil {
		t.Error("InitUser Failed", err, err2)
		return
	}

	alice.StoreFile("alice file", []byte("File File File..!!!!!!"))
	magic_string, err := alice.ShareFile("alice file", "BOB")
	if err != nil {
		t.Error("SharFile Failed", err)
		return
	}

	err = bob.ReceiveFile("bob's file", "ALICE", magic_string)
	if err != nil {
		t.Error("ReceiveFile Failed, ", err)
		return
	}

	alice.StoreFile("alice file2", []byte("File File File..???!!!"))
	magic_string, err = alice.ShareFile("alice file2", "BOB")
	if err != nil {
		t.Error("ShareFile Failed", err)
	}
	decoded_magic_string, err := hex.DecodeString(magic_string)
	if err != nil {
		t.Error("hex DecodeString Failed ", err)
		return
	}

	decoded_magic_string[300] = 3 // Sign Value Changed.
	wrong_sign_magic_string := hex.EncodeToString(decoded_magic_string)
	actual_err := bob.ReceiveFile("bob's file2", "ALICE", wrong_sign_magic_string)
	expected_err := errors.New("crypto/rsa: verification error")
	if !reflect.DeepEqual(actual_err, expected_err) {
		t.Error("Verification Should Fail.", actual_err)
		return
	}

	decoded_magic_string2, _ := hex.DecodeString(magic_string)
	decoded_magic_string2[533] = 2 // File Content Modified.
	wrong_file_magic_string := hex.EncodeToString(decoded_magic_string2)
	actual_err = bob.ReceiveFile("bob's file2", "ALICE", wrong_file_magic_string)
	expected_err = errors.New("crypto/rsa: verification error") // File Content Changed So This error should be triggered.
	if !reflect.DeepEqual(actual_err, expected_err) {
		t.Error("Verification Should Fail.", actual_err)
		return
	}

	decoded_magic_string3, _ := hex.DecodeString(magic_string)
	decoded_magic_string3[2] = 20 // Encrypted SessionKey changed.
	wrong_session_key_magic_string := hex.EncodeToString(decoded_magic_string3)
	err = bob.ReceiveFile("bob's file2", "ALICE", wrong_session_key_magic_string)
	if err == nil {
		t.Error("Session Key Changed Case Fail")

	}




}
