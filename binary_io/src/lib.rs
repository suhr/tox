pub use nom::IResult;
pub use cookie_factory::GenError;

use nom::number::streaming::{le_u8, le_u16};
use nom::{named, map, count};
use cookie_factory::{do_gen, gen_be_u8, gen_le_u16};

use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
};

/// The trait provides method to deserialize struct from raw bytes
pub trait FromBytes : Sized {
    /// Deserialize struct using `nom` from raw bytes
    fn from_bytes(i: &[u8]) -> IResult<&[u8], Self>;
}

/// The trait provides method to serialize struct into raw bytes
pub trait ToBytes : Sized {
    /// Serialize struct into raw bytes using `cookie_factory`
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError>;
}

impl ToBytes for IpAddr {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        match *self {
            IpAddr::V4(ref p) => p.to_bytes(buf),
            IpAddr::V6(ref p) => p.to_bytes(buf),
        }
    }
}

impl FromBytes for Ipv4Addr {
    named!(from_bytes<Ipv4Addr>, map!(count!(le_u8, 4),
        |v| Ipv4Addr::new(v[0], v[1], v[2], v[3])
    ));
}

impl ToBytes for Ipv4Addr {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let o = self.octets();
        do_gen!(buf,
            gen_be_u8!(o[0]) >>
            gen_be_u8!(o[1]) >>
            gen_be_u8!(o[2]) >>
            gen_be_u8!(o[3])
        )
    }
}

impl FromBytes for Ipv6Addr {
    named!(from_bytes<Ipv6Addr>, map!(count!(le_u16, 8),
        |v| Ipv6Addr::new(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7])
    ));
}

impl ToBytes for Ipv6Addr {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        let s = self.segments();
        do_gen!(buf,
            gen_le_u16!(s[0]) >>
            gen_le_u16!(s[1]) >>
            gen_le_u16!(s[2]) >>
            gen_le_u16!(s[3]) >>
            gen_le_u16!(s[4]) >>
            gen_le_u16!(s[5]) >>
            gen_le_u16!(s[6]) >>
            gen_le_u16!(s[7])
        )
    }
}

/// Generator that ensures that length of serialized data does not exceed specified limit.
pub fn gen_len_limit(buf: (&mut [u8], usize), limit: usize) -> Result<(&mut [u8], usize), GenError> {
    if buf.1 <= limit {
        Ok(buf)
    } else {
        Err(GenError::BufferTooSmall(buf.1))
    }
}

/// Generator that returns specified error.
#[allow(clippy::needless_pass_by_value)]
pub fn gen_error(_buf: (&mut [u8], usize), error: u32) -> Result<(&mut [u8], usize), GenError> {
    Err(GenError::CustomError(error))
}
