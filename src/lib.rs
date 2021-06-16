// Originally based on phpass, but they seemed to be
// imitating the non-standard FreeBSD multipass md5, as described:
// https://docs.rs/pwhash/0.3.0/pwhash/md5_crypt/index.html
// except instead of:
// $1${salt}${checksum}
// We look like:
// $P$[passes; 1][salt; 8]{checksum}
pub mod error;
use error::Error;
use rand::{thread_rng, Rng};
use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};
use std::fmt;

#[derive(Debug)]
pub struct PhPass<'a> {
    // Passes as a power of 2**passes
    passes: usize,
    salt: Cow<'a, str>,
    // This will always match 16-bytes, however long it's encoded,
    // because that's how big an MD5 sum is
    hash: [u8; 16],
}

// It'd be nice if the base64 crate gave me access to this.
const CRYPT: &str = r"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

impl<'a> TryFrom<&'a str> for PhPass<'a> {
    type Error = Error;

    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        // TODO: For full old-WordPress support, allow 32-bit hashes
        if s.len() < 34 {
            return Err(Error::OldWPFormat);
        }

        // TODO: were this part of a suite of crypto algos, this ID would
        // choose PHPass.
        if &s[0..3] != "$P$" {
            return Err(Error::InvalidId(s[0..3].to_string()));
        }

        // 4th character, decoded on table, as a power of 2
        // TODO: access the table directly and avoid this overhead,
        // since it's only 1 character
        let passes = s.chars().nth(3);
        let passes = CRYPT
            .find(passes.ok_or(Error::InvalidPasses(passes))?)
            .ok_or(Error::InvalidPasses(passes))?;

        // We pad by 0s, encoded as .
        let encoded = &s[12..];
        let len = encoded.len();
        let hash = base64::decode_config(
            std::iter::repeat(b'.')
                // Base64 encodes on 3-byte boundaries
                .take(3 - len % 3)
                .chain(encoded.bytes().rev())
                .collect::<Vec<_>>(),
            base64::CRYPT,
        )?
        .iter()
        // Then those backwards-fed inputs need their outputs reversed.
        .rev()
        .take(16)
        .copied()
        .collect::<Vec<_>>()
        .as_slice()
        .try_into()?;

        Ok(Self {
            passes,
            salt: Cow::Borrowed(&s[4..12]),
            hash,
        })
    }
}

impl fmt::Display for PhPass<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let iter = self.hash.chunks_exact(3);
        // Remained must have something in 0, maybe something in 1, no 2
        let remain = iter.remainder();
        let end =
            base64::encode_config([0, 0, remain[0]], base64::CRYPT)
                .chars()
                .rev()
                // Get rid of trailing 0s
                .take(2)
                .collect::<String>();

        let mapped = iter
            .map(|chunk| {
                // To work around the wacky ltr on streaming the string, but
                // rtl for reading the bits from the 24-bit sequence, we'll
                base64::encode_config(
                    chunk.iter().rev().copied().collect::<Vec<_>>(),
                    base64::CRYPT,
                )
                .chars()
                .rev()
                .collect::<String>()
            })
            .chain(std::iter::once(end))
            .collect::<String>();

        write!(
            f,
            "$P${}{}{}",
            &CRYPT[self.passes..self.passes + 1],
            self.salt,
            mapped
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let random_salt = PhPass::new("hello").to_string();
        let phpass = PhPass::try_from(random_salt.as_ref()).unwrap();
        assert!(
            phpass.verify("hello").is_ok(),
            "Failed to verify random-salt password hash"
        )
    }

    #[test]
    fn test_verify_parse() {
        let phpass = PhPass::try_from("$P$BgUdq1RzEBYd9Tm/uZC7mz/l5F.x4N1").unwrap();

        assert!(
            phpass.verify("development").is_ok(),
            "Failed to verify parsed password hash"
        )
    }

    #[test]
    fn test_verify_new() {
        let phpass = PhPass::new("world!");

        assert!(
            phpass.verify("world!").is_ok(),
            "Failed to verify random-salt password hash"
        )
    }
}

fn checksum<T: AsRef<[u8]>, U: AsRef<[u8]>>(pass: T, salt: U, passes: usize) -> [u8; 16] {
    let pass = pass.as_ref();
    let salt = salt.as_ref();
    let checksum = (0..1 << passes).fold(md5::compute([salt, pass].concat()), |a, _| {
        md5::compute([&a.0, pass].concat())
    });
    checksum.0
}

impl PhPass<'_> {
    // Make a new PhPass with a random salt
    pub fn new<'a, T: AsRef<[u8]>>(pass: T) -> PhPass<'a> {
        let mut rng = thread_rng();
        let passes = 13;
        let salt = base64::encode(rng.gen::<[u8; 6]>());
        let hash = checksum(&pass, &salt, passes);

        PhPass {
            passes,
            salt: Cow::Owned(salt),
            hash,
        }
    }

    pub fn verify<T: AsRef<[u8]>>(&self, pass: T) -> Result<(), Error> {
        if self.hash == checksum(pass, self.salt.as_ref(), self.passes) {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }
}
