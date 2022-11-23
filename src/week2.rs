

/// Encrypts a message with the Vigenere algorithm using key
pub fn encrypt_vigenere(message: &str, key: &str) -> Result<String, &'static str> {
    // ensure the message and key are of a certain form

    // TODO these could all be done in a single loop, making it faster, but too lazy for now!
    if !message.chars().all(char::is_alphabetic) {
        return Err("message must contain only alphabetic characters");
    }
    for b in message.as_bytes() {
        if b < &97 || b > &122 {
            return Err("message must be all lowercase values");
        }
    }
    if !key.chars().all(char::is_alphabetic) {
        return Err("key must contain only alphabetic characters");
    }
    for b in key.as_bytes() {
        if b < &97 || b > &122 {
            return Err("key must be all lowercase values");
        }
    }

    let key_as_bytes = key.as_bytes();
    let msg_as_bytes = message.as_bytes();
    let key_len = key.len();
    let mut ciphertext = String::new();

    // WARNING: this is probably not a constant time operation, since the
    // % operation will take longer to compute depending on if `i > key_len`

    // iterate through the characters of message, using the appropriate character in k
    // to encrypt it (here encryption is really just an addition of the key byte modulo 26,
    // because there are 26 possible lowercase alphabetic symbols)
    for i in 0..message.len() {
        let key_idx = i % key_len;

        // we shift by 97 because 97 is 'a' in ASCII, and we want to do modular
        // arithmetic modulo 26
        let msg_byte_shifted = msg_as_bytes[i] - 97;
        let key_byte_shifted = key_as_bytes[key_idx] - 97;

        let ciphertext_byte_shifted = (msg_byte_shifted + key_byte_shifted) % 26;
        let ciphertext_byte = ciphertext_byte_shifted + 97;

        ciphertext.push(ciphertext_byte as char);
    }
    Ok(ciphertext)
}

/// Decrypts a ciphertext with the Vigenere algorithm using key
pub fn decrypt_vigenere(ciphertext: &str, key: &str) -> Result<String, &'static str> {
    // ensure the ciphertext and key are of a certain form

    // TODO these could all be done in a single loop, making it faster, but too lazy for now!
    if !ciphertext.chars().all(char::is_alphabetic) {
        return Err("ciphertext must contain only alphabetic characters");
    }
    for b in ciphertext.as_bytes() {
        if b < &97 || b > &122 {
            return Err("ciphertext must be all lowercase values");
        }
    }
    if !key.chars().all(char::is_alphabetic) {
        return Err("key must contain only alphabetic characters");
    }
    for b in key.as_bytes() {
        if b < &97 || b > &122 {
            return Err("key must be all lowercase values");
        }
    }

    let key_as_bytes = key.as_bytes();
    let ciphertext_as_bytes = ciphertext.as_bytes();
    let key_len = key.len();
    let mut plaintext = String::new();

    // WARNING: this is probably not a constant time operation, since the
    // % operation will take longer to compute depending on if `i > key_len`

    // iterate through the characters of ciphertext, using the appropriate character in k
    // to decrypt it (here decryption is really just a subtraction of the key byte modulo 26,
    // because there are 26 possible lowercase alphabetic symbols)
    for i in 0..ciphertext.len() {
        let key_idx = i % key_len;
        
        // we shift by 97 because 97 is 'a' in ASCII, and we want to do modular
        // arithmetic modulo 26
        let ciphertext_byte_shifted = ciphertext_as_bytes[i] - 97;
        let key_byte_shifted: u8 = key_as_bytes[key_idx] - 97 ;
        
        // determine the ciphertext_byte_shifted - key_byte_shifted modulo 26
        let plaintext_byte_shifted = if ciphertext_byte_shifted >= key_byte_shifted {
            ciphertext_byte_shifted - key_byte_shifted
        } else {
            let diff = key_byte_shifted - ciphertext_byte_shifted;
            26 - diff
        }; 
        let plaintext_byte = plaintext_byte_shifted + 97;

        plaintext.push(plaintext_byte as char);
    }
    Ok(plaintext)
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn numeric_invalid_message_characters() {
        assert_eq!(Err("key must contain only alphabetic characters"), encrypt_vigenere("floopol", "1"));
    }

    #[test]
    fn numeric_invalid_key_characters() {
        assert_eq!(Err("message must contain only alphabetic characters"), encrypt_vigenere("1", "ab"));
    }

    #[test]
    fn capitalized_invalid_key_characters() {
        assert_eq!(Err("key must be all lowercase values"), encrypt_vigenere("floopol", "A"));
    }

    #[test]
    fn capitalized_invalid_message_characters() {
        assert_eq!(Err("message must be all lowercase values"), encrypt_vigenere("ABCDE", "abc"));
    }

    #[test]
    fn symbols_invalid_message_characters() {
        assert_eq!(Err("message must contain only alphabetic characters"), encrypt_vigenere("=", "ab"));
    }

    #[test]
    fn symbols_invalid_key_characters() {
        assert_eq!(Err("key must contain only alphabetic characters"), encrypt_vigenere("floop", "==="));
    }

    #[test]
    fn single_letter_encrypt() {
        assert_eq!(encrypt_vigenere("floop", "a"), Ok("floop".to_string()));
    }

    #[test]
    fn small_encrypt() {
        assert_eq!(encrypt_vigenere("floop", "abc"), Ok("fmqoq".to_string()));
    }

    #[test]
    fn divisible_encrypt() {
        assert_eq!(encrypt_vigenere("floopo", "ab"), Ok("fmoppp".to_string()));
    }

    #[test]
    fn not_divisible_encrypt() {
        assert_eq!(encrypt_vigenere("floob", "bca"), Ok("gnopd".to_string()));
    }

    #[test]
    fn single_letter_decrypt() {
        let plaintext = "floop";
        let key = "a";
        let ciphertext = encrypt_vigenere(plaintext, key).unwrap();
        assert_eq!(decrypt_vigenere(ciphertext.as_str(), key), Ok(plaintext.to_string()));
    }

    #[test]
    fn small_decrypt() {
        let plaintext = "floop";
        let key = "abc";
        let ciphertext = encrypt_vigenere(plaintext, key).unwrap();
        assert_eq!(decrypt_vigenere(ciphertext.as_str(), key), Ok(plaintext.to_string()));
    }

    #[test]
    fn divisible_decrypt() {
        let plaintext = "floob";
        let key = "bca";
        let ciphertext = encrypt_vigenere(plaintext, key).unwrap();
        assert_eq!(decrypt_vigenere(ciphertext.as_str(), key), Ok(plaintext.to_string()));
    }

    #[test]
    fn not_divisible_decrypt() {
        let plaintext = "floob";
        let key = "bca";
        let ciphertext = encrypt_vigenere(plaintext, key).unwrap();
        assert_eq!(decrypt_vigenere(ciphertext.as_str(), key), Ok(plaintext.to_string()));
    }

    #[test]
    fn modular_characters_decrypt_1() {
        let plaintext = "zzzz";
        let key = "b";
        let ciphertext = encrypt_vigenere(plaintext, key).unwrap();
        assert_eq!(decrypt_vigenere(ciphertext.as_str(), key), Ok(plaintext.to_string()));
    }

    #[test]
    fn modular_characters_decrypt_2() {
        let plaintext = "zzzz";
        let key = "c";
        let ciphertext = encrypt_vigenere(plaintext, key).unwrap();
        assert_eq!(decrypt_vigenere(ciphertext.as_str(), key), Ok(plaintext.to_string()));
    }

    #[test]
    fn modular_characters_decrypt_3() {
        let plaintext = "xxx";
        let key = "b";
        let ciphertext = encrypt_vigenere(plaintext, key).unwrap();
        assert_eq!(decrypt_vigenere(ciphertext.as_str(), key), Ok(plaintext.to_string()));
    }

    #[test]
    fn modular_characters_decrypt_4() {
        let plaintext = "xxx";
        let key = "z";
        let ciphertext = encrypt_vigenere(plaintext, key).unwrap();
        assert_eq!(decrypt_vigenere(ciphertext.as_str(), key), Ok(plaintext.to_string()));
    }
}