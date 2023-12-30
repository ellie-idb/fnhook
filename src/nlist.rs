//! A re-implementation of the nlist_64 struct from mach-o/nlist.h
use nom::number::complete::{le_u32, u8, le_u16, le_u64};
use nom::IResult;

#[derive(Debug)]
pub(crate) struct Nlist {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

impl Nlist {
    pub(crate) fn parse(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, n_strx) = le_u32(input)?;
        let (input, n_type) = u8(input)?;
        let (input, n_sect) = u8(input)?;
        let (input, n_desc) = le_u16(input)?;
        let (input, n_value) = le_u64(input)?;

        Ok((
            input,
            Self {
                n_strx,
                n_type,
                n_sect,
                n_desc,
                n_value,
            },
        ))
    }
}