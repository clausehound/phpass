// Originally based on the hacky phpass, but they seemed to be
// imitating the non-standard FreeBSD multipass md5, as described:
// https://docs.rs/pwhash/0.3.0/pwhash/md5_crypt/index.html
// except instead of:
// $1${salt}${checksum}
// We look like:
// $P$[passes; 1][salt; 8]{checksum}
mod error;
use base64;
pub use error::Error;
use md5;
use std::convert::{TryFrom, TryInto};

#[derive(Debug)]
pub struct PhPass<'a> {
    passes: usize,
    salt: &'a str,
    // This will always match 16-bytes, however long it's encoded,
    // because that's how big an MD5 sum is
    hash: [u8; 16],
}

// It'd be nice if the base64 crate gave me access to this.
const CRYPT: &str = r"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

impl<'a> TryFrom<&'a str> for PhPass<'a> {
    // TODO Make a better error
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
        let passes = 1
            << CRYPT
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
            salt: &s[4..12],
            hash,
        })
    }
}

impl PhPass<'_> {
    pub fn verify<T: AsRef<[u8]>>(&self, pass: T) -> Result<(), Error> {
        let pass = pass.as_ref();
        let salt = self.salt.as_bytes();
        let checksum = (0..self.passes).fold(md5::compute([salt, pass].concat()), |a, _| {
            md5::compute([&a.0, pass].concat())
        });

        if self.hash == checksum.0 {
            Ok(())
        } else {
            Err(Error::VerificationError)
        }
    }
}
