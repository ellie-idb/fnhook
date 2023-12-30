use std::thread::sleep;
use anyhow::Result;
use dynasmrt::{dynasm, DynasmLabelApi};
use fnhook::platform;
use fnhook::platform::EnumerateResult;
use fnhook::FnHook;
use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_types::mach_vm_address_t;
use mach2::{port::mach_port_t, vm_types::mach_vm_size_t};

struct MyExampleHook {
    //! Our actual hook
    hook: FnHook,
    //! The mach port of the task we want to hook in
    task: mach_port_t,
    //! The address of the "hit flag"
    hit_flag_addr: mach_vm_address_t,
}

impl MyExampleHook {
    //! This function returns a u64 which represents whether or not
    //! the hook code path was taken or not
    pub fn read_hit_flag(&self) -> Result<u64> {
        let bytes = platform::read_task_memory(
            self.task,
            self.hit_flag_addr,
            std::mem::size_of::<u64>() as u64,
        )?;
        let result = u64::from_ne_bytes(bytes.try_into().unwrap_or_default());
        Ok(result)
    }

    //! This function will clear the "hit flag".
    pub fn clear_hit_flag(&self) -> Result<()> {
        platform::write_task_memory(self.task, self.hit_flag_addr, &[0; 8])?;
        Ok(())
    }

    //! This function handles setting up the actual hook from fnhook,
    //! and returns the assembly to be put into the "hook cave"
    pub fn handle_hook(
        hit_flag_addr: mach_vm_address_t,
        orig_ptr: mach_vm_address_t,
    ) -> Result<Vec<u8>> {
        let mut ops = dynasmrt::aarch64::Assembler::new()?;
        dynasm!(ops
            ; .arch aarch64
            ; ->hook:
            ; ldr x14, ->hit_flag_pool
            ; mov x13, #1
            ; str x13, [x14]
            ; ldr x15, ->orig_addr
            ; br x15
            ; ->orig_addr:
            ; .bytes orig_ptr.to_ne_bytes()
            ; ->hit_flag_pool:
            ; .bytes hit_flag_addr.to_ne_bytes()
        );

        let hook = ops.finalize().unwrap();
        Ok(hook.to_vec())
    }

    //! This function creates a new instance of this hook, which wraps around fnhook's
    //! FnHook type.
    pub fn new(module: &str, func: &str, task: mach_port_t) -> Result<Self> {
        let mut base_address: u64 = 0;
        let mut base_size: u64 = 0;
        // find the first memory region that contains our desired module name
        platform::enumerate_task_memory_regions(
            task,
            |_, module_name, module_start, module_size| {
                if let Ok(module_name) = module_name.to_str() {
                    if !module_name.contains(module) {
                        return EnumerateResult::ContinueEnumerating;
                    }
                    base_address = *module_start;
                    base_size = *module_size;
                    return EnumerateResult::StopEnumerating;
                }

                EnumerateResult::ContinueEnumerating
            },
        )?;

        let hit_flag_addr = platform::allocate_task_memory(task, 8, VM_PROT_READ | VM_PROT_WRITE)?;
        platform::write_task_memory(task, hit_flag_addr, &[0; 8])?;

        let Some(hook_fn_addr) =
            FnHook::find_function_stub(task, func, base_address, base_size)?
        else {
            panic!("could not find function stub, bailing");
        };

        println!("hooking fn at addr 0x{hook_fn_addr:08x?}");
        let hook = FnHook::hook_fn(task, hook_fn_addr, |orig_addr| {
            Self::handle_hook(pause_flag_addr, hit_flag_addr, orig_addr)
        })?;

        Ok(Self {
            hook,
            task,
            hit_flag_addr,
            pause_flag_addr,
        })
    }
}

fn main() -> anyhow::Result<()> {
    let module = "MyExampleApplication";
    let pid = platform::get_pid_for_name(module)?;
    let task = platform::task_for_pid(pid)?;

    let hook = MyExampleHook::new(module, "_write", task)?;

    println!("waiting for our hook to be triggered ...");
    while let Ok(hit_flag) = hook.read_hit_flag() {
        if hit_flag != 0 {
            break;
        }
        sleep(std::time::Duration::from_secs(1));
    }
    println!("our hook was triggered! clearing hit flag");
    hook.clear_hit_flag()?;
    Ok(())
}
