//! Bounded asynchronous greetd wire codec (native-endian u32 length + JSON).
use crate::{
    codec::{check_size, Error},
    Request, Response,
};
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[async_trait]
pub trait TokioCodec {
    async fn read_from<T: AsyncReadExt + Unpin + Send>(stream: &mut T) -> Result<Self, Error>
    where
        Self: Sized;
    async fn write_to<T: AsyncWriteExt + Unpin + Send>(&self, stream: &mut T) -> Result<(), Error>;
}
async fn read<T: AsyncReadExt + Unpin + Send, V: DeserializeOwned>(
    stream: &mut T,
) -> Result<V, Error> {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::UnexpectedEof => Error::Eof,
            _ => error.into(),
        })?;
    let length = u32::from_ne_bytes(header) as usize;
    check_size(length)?;
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}
async fn write<T: AsyncWriteExt + Unpin + Send, V: Serialize + Sync>(
    value: &V,
    stream: &mut T,
) -> Result<(), Error> {
    let body = serde_json::to_vec(value)?;
    check_size(body.len())?;
    stream.write_all(&(body.len() as u32).to_ne_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}
#[async_trait]
impl TokioCodec for Request {
    async fn read_from<T: AsyncReadExt + Unpin + Send>(stream: &mut T) -> Result<Self, Error> {
        read(stream).await
    }
    async fn write_to<T: AsyncWriteExt + Unpin + Send>(&self, stream: &mut T) -> Result<(), Error> {
        write(self, stream).await
    }
}
#[async_trait]
impl TokioCodec for Response {
    async fn read_from<T: AsyncReadExt + Unpin + Send>(stream: &mut T) -> Result<Self, Error> {
        read(stream).await
    }
    async fn write_to<T: AsyncWriteExt + Unpin + Send>(&self, stream: &mut T) -> Result<(), Error> {
        write(self, stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn oversized_frames_are_rejected_before_body_read_or_allocation() {
        let bytes = u32::MAX.to_ne_bytes();
        let mut input = bytes.as_slice();
        assert!(matches!(
            Request::read_from(&mut input).await,
            Err(Error::Serialization(_))
        ));
    }
}
