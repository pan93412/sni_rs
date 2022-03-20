//! Allow reading SNI host name from ClientHello asynchronously.
//!
//! Extracted from <https://github.com/BranLwyd/rspd/blob/1bfad8498375f0735c229667608ddd4c23aaf7b2/src/main.rs#L367>

use byteorder::{ByteOrder, NetworkEndian};
use std::cmp::min;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::{
    io::{self, ErrorKind},
    pin,
};

/// Get the Server Name Indication from the ClientHello part
/// of a raw TLS stream asynchronously.
///
/// The reader could be a `TcpStream`.
///
/// It'll throw if the ClientHello is not valid,
/// or the length is invalid.
pub async fn read_sni_host_name_from_client_hello<R: AsyncRead>(
    mut reader: Pin<&mut R>,
) -> io::Result<String> {
    // Handshake message type.
    const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
    let typ = reader.read_u8().await?;
    if typ != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "handshake message not a ClientHello (type {}, expected {})",
                typ, HANDSHAKE_TYPE_CLIENT_HELLO
            ),
        ));
    }

    // Handshake message length.
    let len = read_u24(reader.as_mut()).await?;
    let reader = reader.take(len.into());
    pin!(reader);

    // ProtocolVersion (2 bytes) & random (32 bytes).
    skip(reader.as_mut(), 34).await?;

    // Session ID (u8-length vec), cipher suites (u16-length vec), compression methods (u8-length vec).
    skip_vec_u8(reader.as_mut()).await?;
    skip_vec_u16(reader.as_mut()).await?;
    skip_vec_u8(reader.as_mut()).await?;

    // Extensions.
    let ext_len = reader.read_u16().await?;
    let new_limit = min(reader.limit(), ext_len.into());
    reader.set_limit(new_limit);
    loop {
        // Extension type & length.
        let ext_typ = reader.read_u16().await?;
        let ext_len = reader.read_u16().await?;

        const EXTENSION_TYPE_SNI: u16 = 0;
        if ext_typ != EXTENSION_TYPE_SNI {
            skip(reader.as_mut(), ext_len.into()).await?;
            continue;
        }
        let new_limit = min(reader.limit(), ext_len.into());
        reader.set_limit(new_limit);

        // ServerNameList length.
        let snl_len = reader.read_u16().await?;
        let new_limit = min(reader.limit(), snl_len.into());
        reader.set_limit(new_limit);

        // ServerNameList.
        loop {
            // NameType & length.
            let name_typ = reader.read_u8().await?;

            const NAME_TYPE_HOST_NAME: u8 = 0;
            if name_typ != NAME_TYPE_HOST_NAME {
                skip_vec_u16(reader.as_mut()).await?;
                continue;
            }

            let name_len = reader.read_u16().await?;
            let new_limit = min(reader.limit(), name_len.into());
            reader.set_limit(new_limit);
            let mut name_buf = vec![0; name_len.into()];
            reader.read_exact(&mut name_buf).await?;
            return String::from_utf8(name_buf)
                .map_err(|err| io::Error::new(ErrorKind::InvalidData, err));
        }
    }
}

async fn skip<R: AsyncRead>(reader: Pin<&mut R>, len: u64) -> io::Result<()> {
    let bytes_read = io::copy(&mut reader.take(len), &mut io::sink()).await?;
    if bytes_read < len {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            format!("skip read {} < {} bytes", bytes_read, len),
        ));
    }
    Ok(())
}

async fn skip_vec_u8<R: AsyncRead>(mut reader: Pin<&mut R>) -> io::Result<()> {
    let sz = reader.read_u8().await?;
    skip(reader.as_mut(), sz.into()).await
}

async fn skip_vec_u16<R: AsyncRead>(mut reader: Pin<&mut R>) -> io::Result<()> {
    let sz = reader.read_u16().await?;
    skip(reader.as_mut(), sz.into()).await
}

async fn read_u24<R: AsyncRead>(mut reader: Pin<&mut R>) -> io::Result<u32> {
    let mut buf = [0; 3];
    reader
        .as_mut()
        .read_exact(&mut buf)
        .await
        .map(|_| NetworkEndian::read_u24(&buf))
}
