//! A simple, batteries included library for hooking standard library functions
//! from an external program on macOS. Currently only supports aarch64.
mod error;
mod nlist;
pub mod platform;
use error::{Error, Result};
use mach2::port::mach_port_t;
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use mach_object::{
    LoadCommand, MachCommand, OFile, INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL,
    S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS,
};
use nlist::Nlist;
use nom::IResult;
use std::io::Cursor;

pub struct FnHook {
    task: mach_port_t,
    hook_addr: mach_vm_address_t,
    orig_fn_addr: mach_vm_address_t,
    hook_cave_addr: mach_vm_address_t,
}

fn indirect_sym_parser(input: &[u8]) -> IResult<&[u8], u32> {
    let (input, a) = nom::number::complete::le_u32(input)?;
    Ok((input, a))
}

struct SymbolTableParser<'a> {
    str_table: &'a [u8],
    sym_table: &'a [u8],
}

impl<'a> SymbolTableParser<'a> {
    fn not_null_terminator(input: &[u8]) -> IResult<&[u8], &[u8]> {
        nom::bytes::complete::is_not([0])(input)
    }

    fn get_string(&self, index: usize) -> IResult<&'a [u8], String, nom::error::Error<Vec<u8>>> {
        let slice = &self.str_table[index..];
        match Self::not_null_terminator(slice) {
            Ok((input, string)) => {
                let string = std::str::from_utf8(string).unwrap_or_default();
                Ok((input, string.to_string()))
            }
            Err(x) => Err(x.to_owned()),
        }
    }

    fn parse_entry(&self, input: &'a [u8]) -> IResult<&'a [u8], (Nlist, String)> {
        let (input, nlist) = Nlist::parse(input)?;
        let (_, str) = self.get_string(nlist.n_strx as usize).unwrap_or_default();

        Ok((input, (nlist, str)))
    }

    fn parse(
        &self,
        nsyms: usize,
    ) -> IResult<&'a [u8], Vec<(Nlist, String)>, nom::error::Error<Vec<u8>>> {
        let e = nom::multi::count(|x| self.parse_entry(x), nsyms)(self.sym_table);
        match e {
            Ok((input, nlist)) => Ok((input, nlist)),
            Err(e) => Err(e.to_owned()),
        }
    }
}

impl FnHook {
    pub fn hook_fn<T>(
        task: mach_port_t,
        hook_addr: mach_vm_address_t,
        init_fn: T,
    ) -> Result<Self>
    where
        T: Fn(mach_vm_address_t) -> Result<Vec<u8>>,
    {
        let orig_ptr = platform::read_task_memory(task, hook_addr, 8)?;
        let orig_ptr = u64::from_ne_bytes(orig_ptr.try_into().unwrap());

        let Ok(hook) = init_fn(orig_ptr) else {
            return Err(Error::dynasm().into());
        };

        let hook_cave_addr =
            platform::allocate_task_memory(task, hook.len(), VM_PROT_READ | VM_PROT_WRITE)?;
        platform::write_task_memory(task, hook_cave_addr, &hook)?;
        platform::set_memory_protection(
            task,
            hook_cave_addr,
            hook.len() as mach_vm_size_t,
            0,
            VM_PROT_READ | VM_PROT_EXECUTE,
        )?;
        println!("hook cave at 0x{hook_cave_addr:08x?}");
        println!("writing hook cave pointer to original address 0x{hook_addr:08x?}",);
        platform::write_task_memory(task, hook_addr, &hook_cave_addr.to_ne_bytes())?;
        println!("hooked!");

        Ok(Self {
            task,
            hook_addr,
            orig_fn_addr: orig_ptr,
            hook_cave_addr,
        })
    }

    fn find_text_segment(
        task: mach_port_t,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> Option<LoadCommand> {
        let buf = platform::read_task_memory(task, base_address, base_size).unwrap();
        let mut cursor = Cursor::new(&buf);
        if let Ok(OFile::MachFile { ref commands, .. }) = OFile::parse(&mut cursor) {
            for MachCommand(cmd, _) in commands {
                if let LoadCommand::Segment64 { segname, .. } = cmd {
                    if segname == "__TEXT" {
                        return Some(cmd.clone());
                    }
                }
            }
        }
        None
    }

    fn find_link_edit_segment(
        task: mach_port_t,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> Option<LoadCommand> {
        let buf = platform::read_task_memory(task, base_address, base_size).unwrap();
        let mut cursor = Cursor::new(&buf);
        if let Ok(OFile::MachFile { ref commands, .. }) = OFile::parse(&mut cursor) {
            for MachCommand(cmd, _) in commands {
                if let LoadCommand::Segment64 { segname, .. } = cmd {
                    if segname == "__LINKEDIT" {
                        return Some(cmd.clone());
                    }
                }
            }
        }
        None
    }

    fn find_sym_tab(
        task: mach_port_t,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> Option<LoadCommand> {
        let buf = platform::read_task_memory(task, base_address, base_size).unwrap();
        let mut cursor = Cursor::new(&buf);
        if let Ok(OFile::MachFile { ref commands, .. }) = OFile::parse(&mut cursor) {
            for MachCommand(cmd, _) in commands {
                if let LoadCommand::SymTab { .. } = cmd {
                    return Some(cmd.clone());
                }
            }
        }
        None
    }

    fn find_dyn_sym_tab(
        task: mach_port_t,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> Option<LoadCommand> {
        let buf = platform::read_task_memory(task, base_address, base_size).unwrap();
        let mut cursor = Cursor::new(&buf);
        if let Ok(OFile::MachFile { ref commands, .. }) = OFile::parse(&mut cursor) {
            for MachCommand(cmd, _) in commands {
                if let LoadCommand::DySymTab { .. } = cmd {
                    return Some(cmd.clone());
                }
            }
        }
        None
    }

    fn grab_indirect_sym_table(
        task: mach_port_t,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> Result<Vec<u32>> {
        let dy_sym_tab = Self::find_dyn_sym_tab(task, base_address, base_size).unwrap();
        let LoadCommand::DySymTab {
            nindirectsyms,
            indirectsymoff,
            ..
        } = dy_sym_tab
        else {
            unreachable!()
        };

        if nindirectsyms == 0 {
            return Ok(Vec::default());
        }

        let text_segment = Self::find_text_segment(task, base_address, base_size).unwrap();
        let LoadCommand::Segment64 {
            vmaddr: text_segment_base,
            ..
        } = text_segment
        else {
            unreachable!()
        };

        let link_edit_segment =
            Self::find_link_edit_segment(task, base_address, base_size).unwrap();
        let LoadCommand::Segment64 {
            vmaddr: link_edit_segment_base,
            vmsize: link_edit_segment_size,
            fileoff: link_edit_segment_fileoff,
            ..
        } = link_edit_segment
        else {
            unreachable!()
        };

        let slide = base_address - text_segment_base as u64;
        let link_edit_segment_addr = slide + link_edit_segment_base as u64;
        let indirect_sym_offset =
            usize::try_from(u64::from(indirectsymoff) - link_edit_segment_fileoff as u64)?;

        let buf = platform::read_task_memory(
            task,
            link_edit_segment_addr,
            link_edit_segment_size.try_into().unwrap(),
        )?;

        if let Ok((_, indirect_syms)) = nom::multi::count(
            indirect_sym_parser,
            nindirectsyms as usize,
        )(&buf[indirect_sym_offset..])
        {
            return Ok(indirect_syms);
        }

        Ok(Vec::default())
    }

    fn grab_sym_table(
        task: mach_port_t,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> Result<Vec<(Nlist, String)>> {
        let Some(link_edit_segment) = Self::find_link_edit_segment(task, base_address, base_size)
        else {
            return Err(Error::missing_segment("__LINKEDIT").into());
        };

        let LoadCommand::SymTab {
            symoff,
            nsyms,
            stroff,
            ..
        } = Self::find_sym_tab(task, base_address, base_size).unwrap()
        else {
            unreachable!()
        };

        let text_segment = Self::find_text_segment(task, base_address, base_size).unwrap();
        let LoadCommand::Segment64 {
            vmaddr: text_segment_base,
            ..
        } = text_segment
        else {
            unreachable!()
        };

        let LoadCommand::Segment64 {
            vmaddr: link_edit_segment_base,
            vmsize: link_edit_segment_size,
            fileoff: link_edit_segment_fileoff,
            ..
        } = link_edit_segment
        else {
            unreachable!()
        };

        let text_segment_base = u64::try_from(text_segment_base)?;
        let link_edit_segment_base = u64::try_from(link_edit_segment_base)?;
        let link_edit_segment_size = u64::try_from(link_edit_segment_size)?;
        let link_edit_segment_fileoff = u64::try_from(link_edit_segment_fileoff)?;

        let slide = base_address - text_segment_base;
        let link_edit_segment_addr = slide + link_edit_segment_base;
        let symoff = u64::from(symoff);
        let stroff = u64::from(stroff);
        let actual_sym_off = usize::try_from(symoff - link_edit_segment_fileoff)?;
        let actual_str_off = usize::try_from(stroff - link_edit_segment_fileoff)?;
        let buf = platform::read_task_memory(task, link_edit_segment_addr, link_edit_segment_size)?;
        let sym_table = &buf[actual_sym_off..];
        let str_table = &buf[actual_str_off..];

        let parser = SymbolTableParser {
            str_table,
            sym_table,
        };
        let (_, nlist) = parser.parse(nsyms as usize)?;
        Ok(nlist)
    }

    pub fn find_function_stub(
        task: mach_port_t,
        f: &str,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> Result<Option<mach_vm_address_t>> {
        let Some(text_segment) = Self::find_text_segment(task, base_address, base_size) else {
            return Err(Error::missing_segment("__TEXT").into());
        };

        let LoadCommand::Segment64 {
            vmaddr: text_segment_base,
            ..
        } = text_segment
        else {
            unreachable!()
        };

        let slide = base_address - text_segment_base as u64;

        let sym_tab = Self::grab_sym_table(task, base_address, base_size)?;
        let indirect_sym_tab = Self::grab_indirect_sym_table(task, base_address, base_size)?;

        let buf = platform::read_task_memory(task, base_address, base_size)?;
        let mut cursor = Cursor::new(&buf);

        if let Ok(OFile::MachFile { ref commands, .. }) = OFile::parse(&mut cursor) {
            for MachCommand(cmd, _) in commands {
                if let LoadCommand::Segment64 {
                    sections: text_sections,
                    ..
                } = cmd
                {
                    for section in text_sections
                        .iter()
                        .filter(|x| x.segname == "__DATA" || x.segname == "__DATA_CONST")
                    {
                        match section.flags.sect_type() {
                            S_LAZY_SYMBOL_POINTERS | S_NON_LAZY_SYMBOL_POINTERS => {
                                let indirect_symbol_bindings = platform::read_task_memory(
                                    task,
                                    section.addr as u64 + slide,
                                    section.size as u64,
                                )?;
                                let indirect_sym_tab =
                                    &indirect_sym_tab[section.reserved1 as usize..];
                                for (i, _) in indirect_symbol_bindings
                                    .chunks(8)
                                    .map(|x| u64::from_ne_bytes(x.try_into().unwrap()))
                                    .enumerate()
                                {
                                    let symtab_index = indirect_sym_tab[i];
                                    if symtab_index == INDIRECT_SYMBOL_ABS
                                        || symtab_index == INDIRECT_SYMBOL_LOCAL
                                        || (symtab_index
                                            == INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)
                                    {
                                        continue;
                                    }
                                    let (_, symbol_name) = &sym_tab[symtab_index as usize];
                                    if symbol_name == f {
                                        let addr = i as u64 * 8 + (section.addr as u64 + slide);
                                        return Ok(Some(addr));
                                    }
                                }
                            }
                            _ => (),
                        };
                    }
                }
            }
        }

        Ok(None)
    }
}
