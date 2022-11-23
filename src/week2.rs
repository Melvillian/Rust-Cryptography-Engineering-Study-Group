use core::num;
use std::io;

pub fn encrypt_vigenere(message: &str, key: &str) -> String {

    return "todo".to_string();
}

pub fn decrypt_vigenere(message: &str, key: &str) -> String {
    return "todo".to_string();
}

pub fn extend_key(message: &str, key: &str) -> Result<String, &'static str> {
    let msg_len = message.len();
    let key_len = key.len();

    if (!message.chars().all(char::is_alphabetic)) {
        return Err("message must contain only alphabetic characters");
    }
    if (!key.chars().all(char::is_alphabetic)) {
        return Err("key must contain only alphabetic characters");
    }

    if (msg_len < key_len) {
        return Err("message length too short for key");
    }

    // extend the key by copying it repeatedly to match the length
    // of the message. If the length of the message is not a multiple
    // of the key length, then do some extra work to extend the
    // key length to match the message's length by copying over
    // select characters    
    let num_times_to_repeat = msg_len / key_len;
    let remainder = num_times_to_repeat * key_len;

    let mut extended_key = key.repeat(num_times_to_repeat);

    if (remainder != 0) {
        key.bytes().take(remainder)
        for i in 0..remainder {
            extended_key.push(key[i]);
        }
    }



    return Ok(extended_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_extend_key() {
        assert_eq!("a".to_string(), extend_key("b", "a").unwrap());
    }

    #[test]
    fn long_extend_key() {
        assert_eq!("aaaaa".to_string(), extend_key("floop", "a").unwrap());
    }

    #[test]
    fn divisible_extend_key() {
        assert_eq!("abcabc".to_string(), extend_key("flooop", "abc").unwrap());
    }

    #[test]
    fn not_divisible_extend_key() {
        assert_eq!("abcabcab".to_string(), extend_key("floopol", "abc").unwrap());
    }

    #[test]
    #[should_panic]
    fn invalid_characters_extend_key() {
        extend_key("floopol", "19348");
    }
}