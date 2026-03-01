use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    compress::{deflate_compress, deflate_decompress},
    crypto::aes_gcm,
    error::{RcrocError, Result},
    models::{FileRequest, TransferPlan},
};

use super::comm::{read_frame, write_frame};

const PACKET_CONTROL: u8 = 0x01;
const PACKET_DATA_RAW: u8 = 0x02;
const PACKET_DATA_COMPRESSED: u8 = 0x03;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PlainMessage {
    JoinRoom {
        room: String,
        relay_password: String,
    },
    JoinWaiting,
    JoinOk,
    JoinError {
        message: String,
    },
    KeyInit {
        public_key: Vec<u8>,
    },
    KeyResponse {
        public_key: Vec<u8>,
        salt: Vec<u8>,
    },
    TransferPlan(TransferPlan),
    PlanAck,
    FileRequest(FileRequest),
    FileDone {
        file_index: u32,
    },
    Finished,
    Error {
        message: String,
    },
}

#[derive(Debug, Clone)]
pub enum EncryptedPacket {
    Control(PlainMessage),
    Data {
        file_index: u32,
        position: u64,
        data: Vec<u8>,
        compressed: bool,
    },
}

pub async fn send_plain_message<W>(writer: &mut W, msg: &PlainMessage) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(msg)?;
    write_frame(writer, &payload).await
}

pub async fn recv_plain_message<R>(reader: &mut R) -> Result<PlainMessage>
where
    R: AsyncRead + Unpin,
{
    let payload = read_frame(reader).await?;
    Ok(serde_json::from_slice(&payload)?)
}

pub async fn send_encrypted_packet<W>(
    writer: &mut W,
    key: &[u8; 32],
    packet: &EncryptedPacket,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let plaintext = encode_packet(packet)?;
    let ciphertext = aes_gcm::encrypt(key, &plaintext)?;
    write_frame(writer, &ciphertext).await
}

pub async fn recv_encrypted_packet<R>(reader: &mut R, key: &[u8; 32]) -> Result<EncryptedPacket>
where
    R: AsyncRead + Unpin,
{
    let payload = read_frame(reader).await?;
    let plaintext = aes_gcm::decrypt(key, &payload)?;
    decode_packet(&plaintext)
}

fn encode_packet(packet: &EncryptedPacket) -> Result<Vec<u8>> {
    match packet {
        EncryptedPacket::Control(msg) => {
            let json = serde_json::to_vec(msg)?;
            let mut out = Vec::with_capacity(1 + json.len());
            out.push(PACKET_CONTROL);
            out.extend_from_slice(&json);
            Ok(out)
        }
        EncryptedPacket::Data {
            file_index,
            position,
            data,
            compressed,
        } => {
            let mut body = Vec::with_capacity(12 + data.len());
            body.extend_from_slice(&file_index.to_le_bytes());
            body.extend_from_slice(&position.to_le_bytes());
            body.extend_from_slice(data);

            if *compressed {
                let compressed_body = deflate_compress(&body)?;
                let mut out = Vec::with_capacity(1 + compressed_body.len());
                out.push(PACKET_DATA_COMPRESSED);
                out.extend_from_slice(&compressed_body);
                Ok(out)
            } else {
                let mut out = Vec::with_capacity(1 + body.len());
                out.push(PACKET_DATA_RAW);
                out.extend_from_slice(&body);
                Ok(out)
            }
        }
    }
}

fn decode_packet(data: &[u8]) -> Result<EncryptedPacket> {
    if data.is_empty() {
        return Err(RcrocError::Protocol("empty decrypted packet".to_string()));
    }

    match data[0] {
        PACKET_CONTROL => {
            let msg: PlainMessage = serde_json::from_slice(&data[1..])?;
            Ok(EncryptedPacket::Control(msg))
        }
        PACKET_DATA_RAW => {
            let (file_index, position, chunk) = decode_chunk(&data[1..])?;
            Ok(EncryptedPacket::Data {
                file_index,
                position,
                data: chunk,
                compressed: false,
            })
        }
        PACKET_DATA_COMPRESSED => {
            let decompressed = deflate_decompress(&data[1..])?;
            let (file_index, position, chunk) = decode_chunk(&decompressed)?;
            Ok(EncryptedPacket::Data {
                file_index,
                position,
                data: chunk,
                compressed: true,
            })
        }
        kind => Err(RcrocError::Protocol(format!(
            "unknown encrypted packet kind: {kind}"
        ))),
    }
}

fn decode_chunk(bytes: &[u8]) -> Result<(u32, u64, Vec<u8>)> {
    if bytes.len() < 12 {
        return Err(RcrocError::Protocol("chunk packet too short".to_string()));
    }

    let mut idx = [0u8; 4];
    idx.copy_from_slice(&bytes[..4]);
    let file_index = u32::from_le_bytes(idx);

    let mut pos = [0u8; 8];
    pos.copy_from_slice(&bytes[4..12]);

    Ok((file_index, u64::from_le_bytes(pos), bytes[12..].to_vec()))
}
