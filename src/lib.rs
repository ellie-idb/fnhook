//! A simple, batteries included library for hooking standard library functions
//! from an external program on macOS. Currently only supports aarch64.
mod nlist;
pub mod platform;
use nlist::Nlist;
use mach2::port::mach_port_t;
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use mach_object::{
    LoadCommand, MachCommand, OFile,
    S_LAZY_SYMBOL_POINTERS, S_NON_LAZY_SYMBOL_POINTERS, INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL,
};
use std::io::Cursor;
use nom::IResult;
use platform::KernResult;
use dynasmrt::{dynasm, DynasmLabelApi};

pub struct FnHook {
   task: mach_port_t,
    hooked_addr: mach_vm_address_t,
    pause_flag_addr: mach_vm_address_t,
    hit_flag_addr: mach_vm_address_t,
    hook_cave_addr: Option<mach_vm_address_t>,
}

impl FnHook {
    pub fn read_pause_flag(&self) -> platform::KernResult<u64> {
        let bytes = platform::read_task_memory(
            self.task,
            self.pause_flag_addr,
            std::mem::size_of::<u64>() as u64,
        )?;
        Ok(u64::from_ne_bytes(bytes.try_into().unwrap()))
    }

    pub fn read_hit_flag(&self) -> platform::KernResult<u64> {
        let bytes = platform::read_task_memory(
            self.task,
            self.hit_flag_addr,
            std::mem::size_of::<u64>() as u64,
        )?;
        Ok(u64::from_ne_bytes(bytes.try_into().unwrap()))
    }

    pub fn set_pause_flag(&self, data: u64) -> platform::KernResult<()> {
        platform::write_task_memory(self.task, self.pause_flag_addr, &data.to_ne_bytes())?;
        Ok(())
    }

    pub fn clear_hit_flag(&self) -> platform::KernResult<()> {
        platform::write_task_memory(self.task, self.hit_flag_addr, &[0; 8])?;
        Ok(())
    }

    pub fn hook_fn(&mut self) -> platform::KernResult<()> {
        if self.hook_cave_addr.is_some() {
            return Ok(());
        }

        let mut ops = dynasmrt::aarch64::Assembler::new().unwrap();
        let orig_ptr = platform::read_task_memory(self.task, self.hooked_addr, 8).unwrap();
        println!("{:08x?}", u64::from_le_bytes(orig_ptr.clone().try_into().unwrap()));

        dynasm!(ops
            ; .arch aarch64
            ; ->hook:
            ; ldr x15, ->pause_flag_pool
            ; ldr x15, [x15]
            ; subs x15, x15, #0
            ; cset x15, eq
            ; tbnz x15, #0, ->orig
            ; ldr x14, ->hit_flag_pool
            ; mov x13, #1
            ; str x13, [x14]
            ; b ->hook
            ; ->orig:
            ; ldr x15, ->orig_addr
            ; br x15
            ; ->orig_addr:
            ; .bytes orig_ptr
            ; ->pause_flag_pool:
            ; .bytes self.pause_flag_addr.to_ne_bytes()
            ; ->hit_flag_pool:
            ; .bytes self.hit_flag_addr.to_ne_bytes()
        );

        let hook = ops.finalize().unwrap();
        let hook_cave_addr =
            platform::allocate_task_memory(self.task, hook.len(), VM_PROT_READ | VM_PROT_WRITE)?;
        platform::write_task_memory(self.task, hook_cave_addr, &hook)?;
        platform::set_memory_protection(
            self.task,
            hook_cave_addr,
            hook.len() as mach_vm_size_t,
            0,
            VM_PROT_READ | VM_PROT_EXECUTE,
        )?;
        println!("hook cave at 0x{hook_cave_addr:08x?}");
        println!(
            "writing hook cave pointer to original address 0x{:08x?}",
            self.hooked_addr
        );
        platform::write_task_memory(self.task, self.hooked_addr, &hook_cave_addr.to_ne_bytes())?;
        println!("hooked!");
        self.hook_cave_addr = Some(hook_cave_addr);
        Ok(())
    }

    pub fn new(task: mach_port_t, fn_address: mach_vm_address_t) -> Self {
        let pause_flag_addr =
            platform::allocate_task_memory(task, 8, VM_PROT_READ | VM_PROT_WRITE).unwrap();
        let hit_flag_addr =
            platform::allocate_task_memory(task, 8, VM_PROT_READ | VM_PROT_WRITE).unwrap();
        platform::write_task_memory(task, pause_flag_addr, &[0; 8]).unwrap();
        platform::write_task_memory(task, hit_flag_addr, &[0; 8]).unwrap();
        println!("allocated pause flag at 0x{pause_flag_addr:08x?}");
        println!("allocated hit flag at 0x{hit_flag_addr:08x?}");

        Self {
            task,
            hooked_addr: fn_address,
            pause_flag_addr,
            hit_flag_addr,
            hook_cave_addr: None,
        }
    }

    fn find_text_segment(
        task: mach_port_t,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> Option<LoadCommand> {
        let buf = platform::read_task_memory(task, base_address, base_size).unwrap();
        let mut cursor = Cursor::new(&buf);
        if let Ok(OFile::MachFile {
            ref commands,
            ..
        }) = OFile::parse(&mut cursor)
        {
            for MachCommand(cmd, _) in commands {
                match cmd {
                    LoadCommand::Segment64 { segname, .. } => {
                        if segname == "__TEXT" {
                            return Some(cmd.clone());
                        }
                    }
                    _ => (),
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
        if let Ok(OFile::MachFile {
            ref commands,
            ..
        }) = OFile::parse(&mut cursor)
        {
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
        if let Ok(OFile::MachFile {
            ref commands,
            ..
        }) = OFile::parse(&mut cursor)
        {
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
        if let Ok(OFile::MachFile {
            ref commands,
            ..
        }) = OFile::parse(&mut cursor)
        {
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
    ) -> platform::KernResult<Vec<u32>> {
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
        let indirect_sym_offset = indirectsymoff as u64 - link_edit_segment_fileoff as u64;

        let buf = platform::read_task_memory(
            task,
            link_edit_segment_addr,
            link_edit_segment_size.try_into().unwrap(),
        )?;

        fn parser<'a>(input: &'a [u8]) -> IResult<&[u8], u32> {
            let (input, a) = nom::number::complete::le_u32(input)?;
            Ok((input, a))
        }

        if let Ok((_, indirect_syms)) =
            nom::multi::count(parser, nindirectsyms as usize)(&buf[indirect_sym_offset as usize..])
        {
            return Ok(indirect_syms);
        }

        Ok(Vec::default())
    }

    fn grab_sym_table(
        task: mach_port_t,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> platform::KernResult<Vec<(Nlist, String)>> {
        let link_edit_segment =
            Self::find_link_edit_segment(task, base_address, base_size).unwrap();
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

        let slide = base_address - text_segment_base as u64;
        let link_edit_segment_addr = slide + link_edit_segment_base as u64;
        let actual_sym_off = symoff as u64 - link_edit_segment_fileoff as u64;
        let actual_str_off = stroff as u64 - link_edit_segment_fileoff as u64;
        let buf = platform::read_task_memory(
            task,
            link_edit_segment_addr,
            link_edit_segment_size.try_into().unwrap(),
        )?;
        let sym_table = &buf[actual_sym_off as usize..];
        let str_table = &buf[actual_str_off as usize..];
        struct Parser<'a> {
            str_table: &'a [u8],
        }

        impl<'a> Parser<'a> {
            fn parse(&self, input: &'a [u8]) -> IResult<&'a [u8], (Nlist, String)> {
                let (input, nlist) = Nlist::parse(input)?;
                let (_, str) = nom::bytes::complete::take_until("\0")(
                    &self.str_table[nlist.n_strx as usize..],
                )?;
                Ok((
                    input,
                    (nlist, std::str::from_utf8(str).unwrap().to_string()),
                ))
            }
        }

        let parser = Parser { str_table };
        let (_, nlist) =
            nom::multi::count(|input| parser.parse(input), nsyms as usize)(sym_table).unwrap();
        Ok(nlist)
    }

    pub fn find_function_stub(
        task: mach_port_t,
        f: &str,
        base_address: mach_vm_address_t,
        base_size: mach_vm_size_t,
    ) -> KernResult<Option<mach_vm_address_t>> {
        let text_segment = Self::find_text_segment(task, base_address, base_size).unwrap();
        let LoadCommand::Segment64 {
            vmaddr: text_segment_base,
            ..
        } = text_segment
        else {
            unreachable!()
        };

        let slide = base_address - text_segment_base as u64;

        let sym_tab = Self::grab_sym_table(task, base_address, base_size)?;
        let indirect_sym_tab =
            Self::grab_indirect_sym_table(task, base_address, base_size).unwrap();

        let buf = platform::read_task_memory(task, base_address, base_size)?;
        let mut cursor = Cursor::new(&buf);

        if let Ok(OFile::MachFile {
            ref commands,
            ..
        }) = OFile::parse(&mut cursor)
        {
            for MachCommand(cmd, _) in commands {
                if let LoadCommand::Segment64 {
                    sections: text_sections,
                    ..
                } = cmd
                {
                    for section in text_sections {
                        if section.segname != "__DATA" && section.segname != "__DATA_CONST" {
                            continue;
                        }

                        match section.flags.sect_type() {
                            S_LAZY_SYMBOL_POINTERS | S_NON_LAZY_SYMBOL_POINTERS => {
                                dbg!(section.addr as u64 + slide);
                                let indirect_symbol_bindings = platform::read_task_memory(task, section.addr as u64 + slide, section.size as u64).unwrap();
                                let indirect_sym_tab = &indirect_sym_tab[section.reserved1 as usize..];
                                for (i, _) in indirect_symbol_bindings.chunks(8).map(|x| u64::from_le_bytes(x.try_into().unwrap())).enumerate() {
                                    let symtab_index = indirect_sym_tab[i];
                                    if symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL || (symtab_index == INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL) {
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
