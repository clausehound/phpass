// Originally based on the hacky phpass, but they seemed to be
// imitating the non-standard FreeBSD multipass md5, as described:
// https://docs.rs/pwhash/0.3.0/pwhash/md5_crypt/index.html
// except instead of:
// $1${salt}${checksum}
// We look like:
// $P$[passes; 1][salt; 8]{checksum}
mod error;
use error::Error;
use base64;
use md5;
use std::{
    convert::TryInto,
    str::FromStr,
};

// Mostly a convenience set of fields around slices of the ph-pass hash
#[derive(Debug)]
pub struct PhPass {
    passes: usize,
    salt: [u8; 8],
    // This will always match 16-bytes, however long it's encoded,
    // because that's how big an MD5 sum is
    hash: [u8; 16],
}

// It'd be nice if the base64 crate gave me access to this.
const CRYPT: &str = r"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

impl FromStr for PhPass {
    // TODO Make a better error
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
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

        // We pad by 0s, encoded as ., because that's how phpass does it
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
        // Then those backwards-fed inputs need their outputs reversed,
        // because the people who wrote WP don't know what endian means
        .rev()
        .take(16)
        .copied()
        .collect::<Vec<_>>()
        .as_slice()
        .try_into()?;

        Ok(Self {
            passes,
            salt: (s[4..12].as_bytes()).try_into()?,
            hash,
        })
    }
}

impl PhPass {
   pub fn verify<T: AsRef<[u8]>>(&self, pass: T) -> bool {
        let pass = pass.as_ref();
        let salt = self.salt;
        let checksum = (0..self.passes).fold(md5::compute([&salt, pass].concat()), |a, _| {
            md5::compute([&a.0, pass].concat())
        });

        self.hash == checksum.0
    }
}
