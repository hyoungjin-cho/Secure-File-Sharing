# Secure-File-Sharing
### System Design
#### 1. Structures
        1. User Struct Fields: Username, Password, RSA Private Key, DS Signing Key,
           Map[filename] => File Struct
        2. File Struct Fields: SharingRecord UUID, SharingRecord Encryption Key, SharingRecord
           HMAC Key
        3. SharingRecord Struct Fields: Creator, File UUIDs, File Encryption Keys, File HMAC keys
#### 2. InitUser
        1. Generate RSA/DS pairs of keys. Store public/private keys to Keystore/User struct
        2. Generate key_master from Argon2Key with password/username as its arguments
        3. Generate three more keys from Argon2Key with key_master as Password argument and
           three different Salts
            1. userUUID <- Argon2Key(key_master, username + “UUID”)
            2. encryptionKey <- Argon2Key(key_master, username + “ENC”)
            3. hmacKey <- Argon2Key(key_master, username + “DataHMAC”)
        4. Encrypt/HMAC userdata by using Symmetric encryption with random iv and
           encryptionKey, and hmacKey
        5. Store (encrypted user || HMAC(encrypted user)) to Datastore with userUUID.
#### 3. GetUser
        1. Follow InitUser procedure up to step3 and check hmac, then decrypt the cipher text.
#### 4. StoreFile
        1. Generate two uuids from uuid.New. (FileDataUUID, SharingRecordUUID)
        2. Generate four keys from randomBytes. (symkey1, symkey2, hmackey1, hmackey2)
        3. Initialize File Struct with (SharingRecordUUID, symkey1, hmackey1).
        4. Add it to the map in User Struct: [Filename] => File Struct, and update user to the server.
        5. Initialize SharingRecord Struct with (Username, FileDataUUID, symkey2, hmackey2).
        6. Encrypt/HMAC sharingRecord Struct using symkey1/hmacKey1.
        7. Store (encrypted SharingRecord || HMAC(encrypted sharingRecord)) to Datastore with
           SharingRecordUUID
        8. Encrypt/HMAC fileData using symkey2/hmackey2.
        9. Store (encrypted fileData || HMAC(encrypted fileData)) to Datastore with FileDataUUID.
#### 5. LoadFile
        1. Get File Struct from the map in user with filename.
        2. Get SharingRecord Struct from server, and check hmac, then decrypt it.
        3. Get FileData from server, and check hmac, then decrypt it.
#### 6. AppendFile
        1. Generate uuid and two keys. (uuid_new, symKey, hmacKey)
        2. Encrypt/HMAC new fileData with symKey/hmacKey
        3. Store (encrypted new fileData || HMAC(encrypted new fileData) to the server using
           uuid_new
        4. Get sharingRecord associated with the original file.
        5. Add uuid_new, symKey, and hmacKey to sharingRecord.
        6. Update sharingRecord to the server.
#### 7. ShareFile
        1. Magic_string <= (encrypted Key_session || sign(File Struct) || encrypted File Struct)
            1. encrypted Key_session
                1. Key_session is generated from random Bytes.
                2. Encrypted with recipient’s RSA public key.
            2. sign(File Struct)
                1. File Struct is from the map in user struct with filename
                    1. File Struct contains sharingRecord info, which contains fileData info.
                2. Sign with sender’s Digital Signature Signing Key.
        3. encrypted File Struct
            1. File Struct is encrypted with random iv and Key_session.
#### 8. ReceiveFile
        1. Decrypt the encrypted Key_session using recipient’s RSA private key.
        2. Decrypt the encrypted File Struct using Key_session.
        3. Check Sign with sender’s DS verifying key and decrypted File Struct.
        4. Store File Struct to the map with recipient’s filename and update user to server.
#### 9. RevokeFile
        1. If the user is the creator of the file, delete all data associated with the file, then call
           StoreFile.
        2. If not, return error.
#### 10. Testing Methodology
I split test cases into two parts: Functionality and Security.
In functionality test, I assumed that Datastore server is safe and there are no attacks. Then
I wrote test cases for each functions to verify that whether my implementation meets the
required functionalities.
In security test, I first looked up the data stored in the server to see if it means anything. I
then made some changes to the original data and updated to server. Then, tried to see if my
code returns expected error messages.
