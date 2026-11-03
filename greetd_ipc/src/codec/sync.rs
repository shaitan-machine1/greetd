//! Bounded synchronous greetd wire codec (native-endian u32 length + JSON).
use crate::{
    codec::{check_size, Error},
    Request, Response,
};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};

pub trait SyncCodec {
    fn read_from<T: Read>(stream: &mut T) -> Result<Self, Error>
    where
        Self: Sized;
    fn write_to<T: Write>(&self, stream: &mut T) -> Result<(), Error>;
}
fn read<T: Read, V: DeserializeOwned>(stream: &mut T) -> Result<V, Error> {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => Error::Eof,
            _ => error.into(),
        })?;
    let length = u32::from_ne_bytes(header) as usize;
    check_size(length)?;
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}
fn write<T: Write, V: Serialize>(value: &V, stream: &mut T) -> Result<(), Error> {
    let body = serde_json::to_vec(value)?;
    check_size(body.len())?;
    stream.write_all(&(body.len() as u32).to_ne_bytes())?;
    stream.write_all(&body)?;
    Ok(())
}
impl SyncCodec for Request {
    fn read_from<T: Read>(stream: &mut T) -> Result<Self, Error> {
        read(stream)
    }
    fn write_to<T: Write>(&self, stream: &mut T) -> Result<(), Error> {
        write(self, stream)
    }
}
impl SyncCodec for Response {
    fn read_from<T: Read>(stream: &mut T) -> Result<Self, Error> {
        read(stream)
    }
    fn write_to<T: Write>(&self, stream: &mut T) -> Result<(), Error> {
        write(self, stream)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oversized_frames_are_rejected_before_body_read_or_allocation() {
        assert!(matches!(
            Request::read_from(&mut u32::MAX.to_ne_bytes().as_slice()),
            Err(Error::Serialization(_))
        ));
    }
}
