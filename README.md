## Lab 4: Exploring Encryption Techniques

This repository contains the source code and resources for Lab 4, where we delve into the fascinating world of encryption and implement two fundamental encryption techniques:

1. **Caesar Cipher:** A classic substitution cipher that shifts letters in the alphabet.
2. **Row Transposition Cipher:** A transposition cipher that rearranges letters within a message based on a secret key.

### Project Structure

The repository is structured as follows:

```
Lab4/
├── Caesar/
│   ├── caesar.py      # Implementation of the Caesar Cipher
│   └── test_caesar.py # Unit tests for the Caesar Cipher implementation
└── RowTransposition/
    ├── row_transposition.py      # Implementation of the Row Transposition Cipher
    └── test_row_transposition.py # Unit tests for the Row Transposition Cipher implementation
```

### Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Anmol-STRS/Encrypt.git
   cd Encrypt/Lab4
   ```

2. **Navigate to the desired cipher directory:**
   - For Caesar Cipher: `cd Caesar`
   - For Row Transposition Cipher: `cd RowTransposition`

3. **Run the Python scripts:**
   - To encrypt a message:
     ```bash
     python <cipher_script>.py -e "<message_to_encrypt>" <key>
     ```
   - To decrypt a message:
     ```bash
     python <cipher_script>.py -d "<message_to_decrypt>" <key>
     ```

   **Replace the following:**
     - `<cipher_script>` with either `caesar` or `row_transposition` depending on the chosen cipher.
     - `<message_to_encrypt>` / `<message_to_decrypt>` with the desired text.
     - `<key>` with the encryption key (an integer for Caesar Cipher, a string for Row Transposition Cipher).

**Examples:**

   - Encrypting "Hello, world!" using Caesar Cipher with key 3:
      ```bash
      python caesar.py -e "Hello, world!" 3
      ```
   - Decrypting "Khoor, zruog!" using Caesar Cipher with key 3:
      ```bash
      python caesar.py -d "Khoor, zruog!" 3
      ```
   - Encrypting "Secret message" using Row Transposition Cipher with key "key":
      ```bash
      python row_transposition.py -e "Secret message" key
      ```
   - Decrypting "Serstegae msse" using Row Transposition Cipher with key "key":
      ```bash
      python row_transposition.py -d "Serstegae msse" key
      ```


### Running Unit Tests

To ensure the correctness of the implemented ciphers, you can run the provided unit tests:

```bash
python -m unittest test_<cipher_script>.py
```

Replace `<cipher_script>` with either `caesar` or `row_transposition`.

### Contributing

Feel free to contribute to this project by:

- Implementing additional encryption techniques.
- Enhancing the existing code with new features or optimizations.
- Reporting any issues or bugs encountered.


Let's explore the fascinating world of cryptography together! 🔐 
