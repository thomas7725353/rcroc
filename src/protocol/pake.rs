use p256::{EncodedPoint, PublicKey, ecdh::EphemeralSecret, elliptic_curve::rand_core::OsRng};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    crypto::key_derivation::derive_aes_key,
    error::{RcrocError, Result},
};

use super::message::{PlainMessage, recv_plain_message, send_plain_message};

pub async fn sender_handshake<IO>(io: &mut IO, shared_secret: &str) -> Result<[u8; 32]>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let init = recv_plain_message(io).await?;
    let peer_pub = match init {
        PlainMessage::KeyInit { public_key } => decode_public_key(&public_key)?,
        other => {
            return Err(RcrocError::UnexpectedMessage(format!(
                "expected KeyInit, got {other:?}"
            )));
        }
    };

    let local_secret = EphemeralSecret::random(&mut OsRng);
    let local_pub = EncodedPoint::from(local_secret.public_key())
        .as_bytes()
        .to_vec();

    let shared = local_secret.diffie_hellman(&peer_pub);

    let mut salt = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut salt);

    send_plain_message(
        io,
        &PlainMessage::KeyResponse {
            public_key: local_pub,
            salt: salt.to_vec(),
        },
    )
    .await?;

    let key = derive_aes_key(
        shared.raw_secret_bytes().as_ref(),
        &secret_payload(shared_secret),
        &salt,
    );
    Ok(key)
}

pub async fn receiver_handshake<IO>(io: &mut IO, shared_secret: &str) -> Result<[u8; 32]>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let local_secret = EphemeralSecret::random(&mut OsRng);
    let local_pub = EncodedPoint::from(local_secret.public_key())
        .as_bytes()
        .to_vec();

    send_plain_message(
        io,
        &PlainMessage::KeyInit {
            public_key: local_pub,
        },
    )
    .await?;

    let response = recv_plain_message(io).await?;
    let (peer_public, salt) = match response {
        PlainMessage::KeyResponse { public_key, salt } => (decode_public_key(&public_key)?, salt),
        other => {
            return Err(RcrocError::UnexpectedMessage(format!(
                "expected KeyResponse, got {other:?}"
            )));
        }
    };

    if salt.len() != 8 {
        return Err(RcrocError::Protocol(
            "invalid handshake salt size".to_string(),
        ));
    }

    let shared = local_secret.diffie_hellman(&peer_public);
    let key = derive_aes_key(
        shared.raw_secret_bytes().as_ref(),
        &secret_payload(shared_secret),
        &salt,
    );

    Ok(key)
}

pub fn room_name_from_secret(secret: &str) -> Result<String> {
    let prefix: String = secret.chars().take(4).collect();
    if prefix.chars().count() < 4 {
        return Err(RcrocError::InvalidSecret(
            "secret must contain at least 4 prefix chars".to_string(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(b"croc");
    Ok(hex::encode(hasher.finalize()))
}

fn decode_public_key(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(bytes)
        .map_err(|e| RcrocError::Protocol(format!("invalid public key bytes: {e}")))
}

fn secret_payload(secret: &str) -> String {
    let mut chars = secret.char_indices();
    let fifth = chars.nth(4);
    if let Some((idx, ch)) = fifth
        && ch == '-'
    {
        let next_idx = idx + ch.len_utf8();
        return secret[next_idx..].to_string();
    }
    secret.to_string()
}
