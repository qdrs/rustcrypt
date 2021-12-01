use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use flate2::read::GzDecoder;
use flate2::{write::GzEncoder, Compression};
use rand::{distributions::Alphanumeric, Rng};
use std::io::Write;
use std::str::FromStr;
use std::{fs::File, io::Read};
use thiserror::Error;
use tinyfiledialogs::{open_file_dialog, save_file_dialog};

#[derive(Error, Debug)]
enum RustcryptError {
    #[error("invalid mode: must be either 'encrypt' or 'decrypt'")]
    InvalidMode(String),
    #[error("missing key")]
    MissingKey,
    #[error("invalid key")]
    InvalidKey(String),
    #[error("no file provided")]
    NoFileProvided,
    #[error("missing or broken file")]
    BrokenFile(String),
    #[error("failed reading file")]
    FailedReading(String),
    #[error("failed writing file")]
    FailedWriting(String),
    #[error("failed compressing data")]
    CompressionError(String),
    #[error("failed decompressing data")]
    DecompressionError(String),
    #[error("failed decoding base64 data")]
    DecodeError(String),
    #[error("failed encrypting data")]
    EncryptionError(String),
    #[error("failed decrypting data")]
    DecryptionError(String),
}

enum RustcryptMode {
    Encrypt,
    Decrypt,
}

impl FromStr for RustcryptMode {
    type Err = RustcryptError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "encrypt" => Ok(Self::Encrypt),
            "decrypt" => Ok(Self::Decrypt),
            _ => Err(RustcryptError::InvalidMode(
                "mode must be either 'encrypt' or 'decrypt'".into(),
            )),
        }
    }
}

fn read_file(path: &str) -> Result<Vec<u8>, RustcryptError> {
    let mut buf = Vec::new();
    File::open(path)
        .map_err(|e| RustcryptError::BrokenFile(e.to_string()))?
        .read_to_end(&mut buf)
        .map_err(|e| RustcryptError::FailedReading(e.to_string()))?;
    Ok(buf)
}

fn save_file(path: &str, data: &[u8]) -> Result<(), RustcryptError> {
    File::create(path)
        .map_err(|e| RustcryptError::BrokenFile(e.to_string()))?
        .write_all(data)
        .map_err(|e| RustcryptError::FailedWriting(e.to_string()))?;
    Ok(())
}

fn encrypt_data(data: &[u8], k: &str) -> Result<String, RustcryptError> {
    let mut c = GzEncoder::new(Vec::new(), Compression::default());
    c.write_all(data)
        .map_err(|e| RustcryptError::CompressionError(e.to_string()))?;
    let compressed = c
        .finish()
        .map_err(|e| RustcryptError::CompressionError(e.to_string()))?;

    let key = Key::from_slice(k.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce_str: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect();

    let nonce = Nonce::from_slice(nonce_str.as_bytes()); // 96-bits; unique per message
    let ciphertext = cipher
        .encrypt(nonce, compressed.as_ref())
        .map_err(|e| RustcryptError::EncryptionError(e.to_string()))?;
    let to_encode = format!("{}|{}", nonce_str, base64::encode(&ciphertext));
    let encoded = base64::encode(&to_encode);
    Ok(encoded)
}

fn decrypt_data(data: &str, key: &str) -> Result<Vec<u8>, RustcryptError> {
    let decoded = base64::decode(data).map_err(|e| RustcryptError::DecodeError(e.to_string()))?;
    let decoded_str =
        String::from_utf8(decoded).map_err(|e| RustcryptError::DecodeError(e.to_string()))?;
    let (nonce_str, encoded_ciphertext) = decoded_str
        .split_once('|')
        .ok_or_else(|| RustcryptError::DecodeError("missing nonce".into()))?;

    let nonce = Nonce::from_slice(nonce_str.as_bytes());
    let ciphertext = base64::decode(encoded_ciphertext)
        .map_err(|e| RustcryptError::DecodeError(e.to_string()))?;

    let key = Key::from_slice(key.as_bytes());
    let cipher = Aes256Gcm::new(key);
    let compressed = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| RustcryptError::DecryptionError(e.to_string()))?;

    let mut d = GzDecoder::new(compressed.as_slice());
    let mut decompressed = Vec::new();
    d.read_to_end(&mut decompressed)
        .map_err(|e| RustcryptError::DecompressionError(e.to_string()))?;

    Ok(decompressed)
}

fn main() -> Result<(), RustcryptError> {
    let matches = clap::App::new("Rustcrypt")
        .arg(
            clap::Arg::with_name("mode")
                .short("m")
                .long("mode")
                .help("rustcrypt mode: either 'encrypt' or 'decrypt'")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("key")
                .short("k")
                .long("key")
                .help("the encryption / decryption key")
                .takes_value(true)
                .required(true),
        )
        .arg(
            clap::Arg::with_name("input")
                .short("i")
                .long("input")
                .help("input file")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("output")
                .short("o")
                .long("output")
                .help("output file")
                .takes_value(true),
        )
        .get_matches();

    let mode = RustcryptMode::from_str(matches.value_of("mode").unwrap())?;
    let key = matches.value_of("key").ok_or(RustcryptError::MissingKey)?;
    if key.len() != 32 {
        let err_str = format!(
            "key length must be 32 characters, given key is {} characters",
            key.len()
        );
        return Err(RustcryptError::InvalidKey(err_str));
    }

    let input = match matches.value_of("input") {
        Some(f) => Some(String::from(f)),
        None => open_file_dialog("select input file", ".", None),
    }
    .ok_or(RustcryptError::NoFileProvided)?;

    let output = match matches.value_of("output") {
        Some(f) => Some(String::from(f)),
        None => save_file_dialog("select output file", "."),
    }
    .ok_or(RustcryptError::NoFileProvided)?;

    match mode {
        RustcryptMode::Encrypt => {
            let input_file = read_file(&input)?;
            let encrypted = encrypt_data(&input_file, key)?;
            save_file(&output, encrypted.as_bytes())?;
        }
        RustcryptMode::Decrypt => {
            let input_file = read_file(&input)?;
            let decoded = String::from_utf8(input_file)
                .map_err(|e| RustcryptError::DecodeError(e.to_string()))?;
            let decrypted = decrypt_data(&decoded, key)?;
            save_file(&output, &decrypted)?;
        }
    };

    Ok(())
}
