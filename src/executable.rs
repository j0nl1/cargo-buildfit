use anyhow::{Result, bail};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
};

fn word(bytes: &[u8], little: bool) -> u32 {
    let data = bytes.try_into().unwrap();
    if little {
        u32::from_le_bytes(data)
    } else {
        u32::from_be_bytes(data)
    }
}
fn wide(bytes: &[u8], little: bool) -> u64 {
    let data = bytes.try_into().unwrap();
    if little {
        u64::from_le_bytes(data)
    } else {
        u64::from_be_bytes(data)
    }
}
fn thin(file: &mut File, offset: u64, size: u64) -> Result<()> {
    if size < 32 {
        bail!("truncated Mach-O retained");
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; 32];
    file.read_exact(&mut header)?;
    let little = match header[..4] {
        [0xce, 0xfa, 0xed, 0xfe] | [0xcf, 0xfa, 0xed, 0xfe] => true,
        [0xfe, 0xed, 0xfa, 0xce] | [0xfe, 0xed, 0xfa, 0xcf] => false,
        _ => bail!("unsupported Mach-O slice retained"),
    };
    if word(&header[12..16], little) != 2 {
        bail!("non-executable Mach-O retained");
    }
    Ok(())
}
pub fn verify(file: &mut File) -> Result<()> {
    let size = file.metadata()?.len();
    let mut header = [0u8; 18];
    file.read_exact(&mut header)?;
    if &header[..2] == b"MZ" {
        return pe(file, size);
    }
    if &header[..4] == b"\x7fELF" {
        if cfg!(target_os = "linux")
            && header[5] == 1
            && [2, 3].contains(&header[16])
            && header[17] == 0
        {
            return Ok(());
        }
        bail!("unsupported ELF executable retained");
    }
    let (little, fat64) = match header[..4] {
        [0xca, 0xfe, 0xba, 0xbe] => (false, false),
        [0xbe, 0xba, 0xfe, 0xca] => (true, false),
        [0xca, 0xfe, 0xba, 0xbf] => (false, true),
        [0xbf, 0xba, 0xfe, 0xca] => (true, true),
        _ => return thin(file, 0, size),
    };
    let count = word(&header[4..8], little) as usize;
    if count == 0 || count > 32 {
        bail!("ambiguous universal executable retained");
    }
    let stride = if fat64 { 32 } else { 20 };
    let table_end = 8 + count * stride;
    let mut table = vec![0u8; count * stride];
    file.seek(SeekFrom::Start(8))?;
    file.read_exact(&mut table)?;
    let mut ranges = Vec::new();
    for entry in table.chunks_exact(stride) {
        let offset = if fat64 {
            wide(&entry[8..16], little)
        } else {
            word(&entry[8..12], little) as u64
        };
        let length = if fat64 {
            wide(&entry[16..24], little)
        } else {
            word(&entry[12..16], little) as u64
        };
        let end = offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("overflowing universal executable"))?;
        if offset < table_end as u64
            || end > size
            || ranges.iter().any(|&(a, b)| offset < b && end > a)
        {
            bail!("invalid universal executable retained");
        }
        thin(file, offset, length)?;
        ranges.push((offset, end));
    }
    Ok(())
}

fn pe(file: &mut File, size: u64) -> Result<()> {
    if size < 64 {
        bail!("truncated PE executable retained");
    }
    file.seek(SeekFrom::Start(60))?;
    let mut offset = [0u8; 4];
    file.read_exact(&mut offset)?;
    let offset = u64::from(u32::from_le_bytes(offset));
    if offset < 64 || offset.saturating_add(24) > size {
        bail!("invalid PE header retained");
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut coff = [0u8; 24];
    file.read_exact(&mut coff)?;
    if &coff[..4] != b"PE\0\0" {
        bail!("invalid PE signature retained");
    }
    let flags = u16::from_le_bytes(coff[22..24].try_into()?);
    if flags & 2 == 0 || flags & 0x2000 != 0 {
        bail!("PE object or library retained");
    }
    let optional = u64::from(u16::from_le_bytes(coff[20..22].try_into()?));
    if optional < 2 || offset.saturating_add(24).saturating_add(optional) > size {
        bail!("invalid PE optional header retained");
    }
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic)?;
    if ![0x10b, 0x20b].contains(&u16::from_le_bytes(magic)) {
        bail!("unsupported PE executable retained");
    }
    Ok(())
}
