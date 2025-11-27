# Part B: GPG Encryption Process Explanation

This document outlines the steps taken to encrypt the student information file using GPG, as required for the Computer Security assignment.

## 1. Preparation

### Student Information File
First, a plain text file named `student_info.txt` was created containing the required student details:

```text
COMPUTER SECURITY
ID: 4123456789
NAME: GOOD STUDENT
```
> Change the ID and name to your own.

### Public Key
The public key provided in the instructions was saved to a file named `public_key.asc`.

## 2. Importing the Public Key

To encrypt the file for the recipient, their public key must first be added to the local GPG keyring.

**Command:**
```bash
gpg --import public_key.asc
```

**Explanation:**
- `gpg`: The GNU Privacy Guard command-line tool.
- `--import`: Imports the keys from the specified file into the local keyring.

**Output:**
The key for "Krerk Piromsopa (Security class) <krerk.p@chula.ac.th>" was successfully imported.

## 3. Encryption

The `student_info.txt` file was encrypted using the imported public key.

**Command:**
```bash
gpg --encrypt --armor --recipient "krerk.p@chula.ac.th" --trust-model always --output student_info.txt.asc student_info.txt
```

**Explanation of Flags:**
- `--encrypt`: Tells GPG to encrypt data.
- `--armor`: Create ASCII armored output. This produces a text-based output (starting with `-----BEGIN PGP MESSAGE-----`) instead of binary, which is safer for email or text transfer.
- `--recipient "krerk.p@chula.ac.th"`: Specifies the recipient of the encrypted message. The message can only be decrypted by the private key corresponding to this public key.
- `--trust-model always`: Forces GPG to trust the key without manual verification (useful for automated scripts or when the key fingerprint hasn't been manually verified).
- `--output student_info.txt.asc`: Specifies the name of the output encrypted file.
- `student_info.txt`: The input file to be encrypted.

## 4. Verification

After encryption, the output file was verified to ensure it is a valid OpenPGP message and encrypted for the correct recipient.

**Command:**
```bash
gpg --list-packets student_info.txt.asc
```

**Result:**
The output confirmed that the file is encrypted with:
- **Key ID**: `6BF63DD3BF33B1F3`
- **User ID**: "Krerk Piromsopa (Security class) <krerk.p@chula.ac.th>"

This confirms that the file `student_info.txt.asc` is correctly encrypted and ready for submission.
