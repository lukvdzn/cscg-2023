use std::io;
use std::io::Read;
use region::Protection;
use nix::unistd::alarm;
use nix::sys::signal::*;
use unicorn_engine::{Unicorn, InsnSysX86, RegisterX86};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, uc_error, HookType};

static STACK_ADDR: u64 = 0x700000;
static STACK_SIZE: u64 = 1024*1024;
static BASE_ADDR: u64 = 0x400000;
static IMG_SIZE: u64 = 1024*1024;
static TIMEOUT: u32 = 60;

// Ignore me
extern fn signal_handler(_signal: i32) {
    panic!("[!] Timed out...")
}

// Emulate bytecode using unicorn
// Checking for syscall and sysenter for sEcUrItY reasons
fn emulate_bytecode(code: &Vec<u8>) -> Result<(), uc_error> {
    let mut unicorn = Unicorn::new(Arch::X86, Mode::MODE_64)?;
    let emu = &mut unicorn;

    // Setup Memory
    emu.mem_map(BASE_ADDR, IMG_SIZE as usize, Permission::ALL)?;
    emu.mem_map(STACK_ADDR, STACK_SIZE as usize, Permission::ALL)?;
    emu.mem_write(BASE_ADDR, code)?;
    
    // Setup Registers
    emu.reg_write(RegisterX86::RSP, STACK_ADDR + STACK_SIZE - 1)?;

    // Add hooks
    emu.add_insn_sys_hook(InsnSysX86::SYSCALL, 1, 0, |uc| {
        panic!("[!] Syscall detected: {uc:?}");
    })?;
    emu.add_insn_sys_hook(InsnSysX86::SYSENTER, 1, 0, |uc| {
        panic!("[!] Sysenter detected: {uc:?}");
    })?;

    emu.add_code_hook(1, 0, |uc, a, s| {
        let rbx = uc.reg_read(RegisterX86::RBX).unwrap();
        println!("[.] Executing code at 0x{:X}, Instruction size: {:X}, RBX: {:X}", a, s, rbx);
    });

    // Run emulation
    emu.emu_start(BASE_ADDR, (BASE_ADDR as usize + code.len()) as u64, 0, 0)?;
    Ok(())
}

fn main() {
    // Ignore me
    let handler = SigHandler::Handler(signal_handler);
    unsafe { signal(Signal::SIGALRM, handler)}.unwrap();
    alarm::set(TIMEOUT);

    let mut user_input: Vec<u8> = Vec::new();
    //io::stdin().read_to_end(&mut user_input).unwrap();
    for i in io::stdin().bytes() {
        match i.unwrap() {
            0x00 => break,
            x => user_input.push(x),
        }
    }

   println!("{:?}", user_input);
   // return

    println!("[+] Checking for malicious instructions...");
    match emulate_bytecode(&user_input) {
        Ok(_) => println!("[+] Looks 100% secure to run this on the host machine"),
        Err(err) => panic!("[!] Emulation failed {err:?}"),
    };
}