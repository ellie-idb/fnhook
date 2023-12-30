//! A simple library for working with the Mach subsystem in a safe-ish way.
use libc::{c_int, c_void, pid_t, proc_regionfilename, uintptr_t, vm_prot_t, vm_size_t};
use libproc::libproc::proc_pid;
use libproc::processes;
use mach2::boolean::boolean_t;
use mach2::message::mach_msg_type_number_t;
use mach2::vm::{
    mach_vm_allocate, mach_vm_copy, mach_vm_protect, mach_vm_region_recurse, mach_vm_write,
};
use mach2::vm_prot::{
    VM_PROT_COPY, VM_PROT_EXECUTE, VM_PROT_NONE, VM_PROT_NO_CHANGE, VM_PROT_READ,
    VM_PROT_WANTS_COPY, VM_PROT_WRITE,
};
use mach2::vm_region::{
    vm_region_submap_info_64, SM_COW, SM_EMPTY, SM_PRIVATE, SM_PRIVATE_ALIASED, SM_SHARED,
    SM_SHARED_ALIASED, SM_TRUESHARED,
};
use mach2::vm_statistics::VM_FLAGS_ANYWHERE;

use mach2::kern_return::KERN_SUCCESS;
use mach2::port::{mach_port_name_t, mach_port_t, MACH_PORT_NULL};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use system_error::Error;

pub type KernResult<T> = Result<T, Error>;

type Pid = pid_t;

pub fn get_pid_for_name(name: &str) -> KernResult<Pid> {
    let pids = processes::pids_by_type(processes::ProcFilter::All).unwrap();
    let pid = pids
        .iter()
        .find(|pid| proc_pid::name(i32::try_from(**pid).unwrap()).unwrap() == name);
    pid.map_or_else(
        || Err(Error::last_os_error()),
        |pid| Ok(i32::try_from(*pid).unwrap()),
    )
}

pub fn task_for_pid(pid: Pid) -> KernResult<mach_port_name_t> {
    if pid == unsafe { libc::getpid() } as Pid {
        return Ok(unsafe { mach2::traps::mach_task_self() });
    }

    let mut task: mach_port_name_t = MACH_PORT_NULL;

    unsafe {
        let result =
            mach2::traps::task_for_pid(mach2::traps::mach_task_self(), pid as c_int, &mut task);
        if result != KERN_SUCCESS {
            return Err(Error::from_raw_kernel_error(result));
        }
    }

    Ok(task)
}

mod traps {
    use mach2::{kern_return::kern_return_t, port::mach_port_name_t};

    extern "C" {
        pub fn pid_for_task(task: mach_port_name_t, pid: *mut ::libc::c_int) -> kern_return_t;
    }
}

pub fn pid_for_task(task: mach_port_t) -> KernResult<pid_t> {
    unsafe {
        let mut pid: libc::c_int = 0;
        let result = traps::pid_for_task(task, std::ptr::addr_of_mut!(pid));
        if result != KERN_SUCCESS {
            return Err(system_error::Error::from_raw_kernel_error(result));
        }
        Ok(pid)
    }
}

fn fmt_memory_protection(prot: i32) -> String {
    let mut ret = String::default();
    if prot & VM_PROT_READ != 0 {
        ret.push('r');
    }
    if prot & VM_PROT_WRITE != 0 {
        ret.push('w');
    }
    if prot & VM_PROT_EXECUTE != 0 {
        ret.push('x');
    }
    if prot & VM_PROT_COPY != 0 {
        ret.push('c');
    }
    if prot & VM_PROT_NO_CHANGE != 0 {
        ret.push('n');
    }
    if prot & VM_PROT_WANTS_COPY != 0 {
        ret.push('w');
    }
    if prot == VM_PROT_NONE {
        ret.push_str("n/a");
    }
    ret
}

fn fmt_share_mode(mode: u8) -> String {
    let mut ret = String::default();
    ret.push_str(match mode {
        SM_COW => "COW",
        SM_PRIVATE => "PRV",
        SM_EMPTY => "NUL",
        SM_SHARED => "ALI",
        SM_TRUESHARED => "SHR",
        SM_PRIVATE_ALIASED => "P/A",
        SM_SHARED_ALIASED => "S/A",
        _ => "???",
    });
    ret
}

pub fn scan_memory_region(
    task: &mach_port_t,
    data: &[u8],
    address: &mach_vm_address_t,
    size: &mach_vm_size_t,
) -> KernResult<Option<mach_vm_address_t>> {
    let mut buf: Vec<u8> = Vec::default();
    buf.resize(1024 * 1024 * 2, 0);

    let mut address = *address;
    let mut size = *size;
    while size >= data.len() as u64 {
        unsafe {
            let mut out_size: u64 = 0;
            let ret = mach2::vm::mach_vm_read_overwrite(
                *task,
                address,
                buf.len() as u64,
                buf.as_mut_ptr() as mach_vm_address_t,
                std::ptr::addr_of_mut!(out_size),
            );
            if ret != KERN_SUCCESS {
                return Err(Error::from_raw_kernel_error(ret));
            }
            if out_size <= data.len() as u64 {
                break;
            }
            for i in 0..out_size - data.len() as u64 {
                let window_start = i;
                let window_end = i + data.len() as u64;
                let window = &buf
                    [usize::try_from(window_start).unwrap()..usize::try_from(window_end).unwrap()];
                if window == data {
                    return Ok(Some(address + i));
                }
            }
            address += out_size;
            if out_size > size {
                break;
            }
            size -= out_size;
        }
    }

    Ok(None)
}

pub fn scan_memory_region_multi(
    task: &mach_port_t,
    data: &[u8],
    address: &mach_vm_address_t,
    size: &mach_vm_size_t,
) -> Option<Vec<uintptr_t>> {
    let mut matches: Vec<uintptr_t> = Vec::default();
    let mut buf: Vec<u8> = Vec::default();
    buf.resize(1024 * 1024 * 2, 0);

    let mut address = *address;
    let mut size = *size;
    while size >= data.len() as u64 {
        unsafe {
            let mut out_size: u64 = 0;
            let ret = mach2::vm::mach_vm_read_overwrite(
                *task,
                address,
                buf.len() as u64,
                buf.as_mut_ptr() as mach_vm_address_t,
                std::ptr::addr_of_mut!(out_size),
            );
            if ret != KERN_SUCCESS {
                break;
            }
            if out_size <= data.len() as u64 {
                break;
            }
            for i in 0..usize::try_from(out_size).unwrap() - data.len() {
                let window_start = i;
                let window_end = i + data.len();
                let window = &buf[window_start..window_end];
                if window == data {
                    matches.push(usize::try_from(address).unwrap() + i);
                }
            }
            address += out_size;
            if out_size > size {
                break;
            }
            size -= out_size;
        }
    }

    if matches.is_empty() {
        None
    } else {
        Some(matches)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnumerateResult {
    StopEnumerating,
    ContinueEnumerating,
}

pub fn enumerate_task_memory_regions<F>(task: mach_port_t, mut f: F) -> KernResult<()>
where
    F: FnMut(
        &mach2::vm_region::vm_region_submap_info_64,
        &std::ffi::CStr,
        &mach_vm_address_t,
        &mach_vm_size_t,
    ) -> EnumerateResult,
{
    let pid = pid_for_task(task)?;
    let mut nesting_depth = 2048;
    let mut address: mach_vm_address_t = 0;
    let mut size: mach_vm_size_t = 0;
    loop {
        let mut info: mach2::vm_region::vm_region_submap_info_64 =
            vm_region_submap_info_64::default();
        let mut count: mach_msg_type_number_t = 19;
        unsafe {
            let result = mach_vm_region_recurse(
                task,
                std::ptr::addr_of_mut!(address),
                std::ptr::addr_of_mut!(size),
                std::ptr::addr_of_mut!(nesting_depth),
                std::ptr::addr_of_mut!(info) as *mut i32,
                std::ptr::addr_of_mut!(count),
            );
            if result != KERN_SUCCESS {
                break;
            }

            if info.is_submap == 1 {
                nesting_depth += 1;
            } else {
                let mut str: [u8; 4096] = [0; 4096];
                let ret = proc_regionfilename(
                    pid,
                    address,
                    std::ptr::addr_of_mut!(str) as *mut c_void,
                    4096,
                );
                if ret < 0 {
                    return Err(Error::from_raw_os_error(ret));
                }
                let module = std::ffi::CStr::from_bytes_until_nul(&str).unwrap();
                if f(&info, module, &address, &size) == EnumerateResult::StopEnumerating {
                    break;
                }
                address += size;
            }
        }
    }

    Ok(())
}

pub fn scan_task_memory_regions(
    task: mach_port_t,
    data: &[u8],
    prot: vm_prot_t,
) -> Option<mach_vm_address_t> {
    let mut result: Option<mach_vm_address_t> = None;
    enumerate_task_memory_regions(
        task,
        |info, module_name, module_start: &u64, module_size| {
            if info.protection & prot == 0 {
                return EnumerateResult::ContinueEnumerating;
            }
            println!(
                "scanning region {module_name:?} from {module_start:08x?} to {:08x?}",
                module_start + module_size
            );
            scan_memory_region(&task, data, module_start, module_size).map_or(
                EnumerateResult::ContinueEnumerating,
                |result_addr| {
                    result = result_addr;
                    EnumerateResult::StopEnumerating
                },
            )
        },
    )
    .unwrap();
    result
}

pub fn scan_task_memory_region_multi(
    task: mach_port_t,
    data: &[u8],
    prot: vm_prot_t,
) -> Option<Vec<usize>> {
    let mut result: Vec<usize> = Vec::default();
    enumerate_task_memory_regions(task, |info, module_name, module_start, module_size| {
        if info.protection & prot == 0 {
            return EnumerateResult::ContinueEnumerating;
        }
        println!(
            "scanning region {module_name:?} from {module_start:08x?} to {:08x?}",
            module_start + module_size
        );
        if let Some(mut region_results) =
            scan_memory_region_multi(&task, data, module_start, module_size)
        {
            println!("found {:} instances in region", region_results.len());
            result.append(&mut region_results);
        }
        EnumerateResult::ContinueEnumerating
    })
    .unwrap();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

pub fn dump_task_memory_regions(task: mach_port_t) {
    enumerate_task_memory_regions(task, |info, module_name, module_start, module_size| {
        println!(
            "{module_name:?} {:08x?} - {:08x?} {:} {:} {:}",
            module_start,
            module_start + module_size,
            fmt_memory_protection(info.protection),
            fmt_memory_protection(info.max_protection),
            fmt_share_mode(info.share_mode)
        );
        EnumerateResult::ContinueEnumerating
    })
    .unwrap();
}

pub fn read_task_memory(
    task: mach_port_t,
    address: mach_vm_address_t,
    len: mach_vm_size_t,
) -> KernResult<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::default();
    buf.resize(usize::try_from(len).unwrap(), 0);

    unsafe {
        let mut out_size: u64 = 0;
        let ret = mach2::vm::mach_vm_read_overwrite(
            task,
            address,
            len,
            buf.as_mut_ptr() as mach_vm_address_t,
            std::ptr::addr_of_mut!(out_size),
        );
        if ret != KERN_SUCCESS {
            return Err(Error::from_raw_kernel_error(ret));
        }
        buf.set_len(usize::try_from(len).unwrap());
    }

    Ok(buf)
}

pub fn allocate_task_memory(
    task: mach_port_t,
    len: vm_size_t,
    prot: vm_prot_t,
) -> KernResult<mach_vm_address_t> {
    unsafe {
        let mut address: mach_vm_address_t = 0;
        let ret = mach_vm_allocate(
            task,
            std::ptr::addr_of_mut!(address),
            len as u64,
            VM_FLAGS_ANYWHERE,
        );
        if ret != KERN_SUCCESS {
            return Err(Error::from_raw_kernel_error(ret));
        }
        let ret = mach_vm_protect(task, address, len as u64, 0, prot);
        if ret != KERN_SUCCESS {
            return Err(system_error::Error::from_raw_kernel_error(ret));
        }
        Ok(address as mach_vm_address_t)
    }
}

pub fn set_memory_protection(
    task: mach_port_t,
    address: mach_vm_address_t,
    len: mach_vm_size_t,
    set_maximum: boolean_t,
    new_prot: vm_prot_t,
) -> KernResult<()> {
    unsafe {
        let ret = mach_vm_protect(task, address, len, set_maximum, new_prot);
        if ret != KERN_SUCCESS {
            return Err(Error::from_raw_kernel_error(ret));
        }
        Ok(())
    }
}

pub fn write_task_memory(
    task: mach_port_t,
    address: mach_vm_address_t,
    data: &[u8],
) -> KernResult<usize> {
    unsafe {
        let mut data = Vec::from(data);
        let ret = mach_vm_write(
            task,
            address,
            data.as_mut_ptr() as uintptr_t,
            data.len().try_into().unwrap(),
        );
        if ret != KERN_SUCCESS {
            return Err(Error::from_raw_kernel_error(ret));
        }
        Ok(data.len())
    }
}

pub fn copy_task_memory(
    task: mach_port_t,
    src_address: mach_vm_address_t,
    dest_address: mach_vm_address_t,
    size: mach_vm_size_t,
) -> KernResult<mach_vm_size_t> {
    unsafe {
        let kret = mach_vm_copy(task, src_address, size, dest_address);
        if kret != KERN_SUCCESS {
            return Err(Error::from_raw_kernel_error(kret));
        }
        Ok(size)
    }
}
