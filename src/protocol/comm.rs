use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    error::{RcrocError, Result},
    models::{COMM_MAGIC, COMM_MAX_FRAME_LEN},
};

pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > COMM_MAX_FRAME_LEN {
        return Err(RcrocError::Protocol(format!(
            "frame too large: {} bytes",
            payload.len()
        )));
    }

    writer.write_all(COMM_MAGIC).await?;
    writer
        .write_all(&(payload.len() as u32).to_le_bytes())
        .await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R>(reader: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).await?;
    if &magic != COMM_MAGIC {
        return Err(RcrocError::Protocol("invalid frame magic".to_string()));
    }

    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;

    if len > COMM_MAX_FRAME_LEN {
        return Err(RcrocError::Protocol(format!(
            "frame too large: {len} bytes"
        )));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}
