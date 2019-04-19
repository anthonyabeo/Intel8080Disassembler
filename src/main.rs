use std::fs::File;
use std::path::Path;
use std::process;
use std::error::Error;
use std::env;
use std::io::Read;


fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} - Game ROM file not provided", &args[0]);
        process::exit(1);
    }

    let mut f = match File::open(Path::new(&args[1])) {
        Ok(file) => file,
        Err(e) => {
            println!("{}", e.description());
            process::exit(1);
        }
    };
    
    let size = f.metadata().unwrap().len() as usize;

    let mut buf = vec![0_u8; size];
    f.read(&mut buf).unwrap();

    // println!("{:?}", buf);
    let mut pc = 0_usize;

    while pc < 100 {
        print!("{}: ", format!("{:04x}", pc));
        match buf[pc] {
            0x00 => { println!("NOP"); pc += 1; }
            0x01 => { 
                print!("LXI B, {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0x02 => { println!("STAX B"); pc += 1; }
            0x03 => { println!("INX B"); pc += 1; }
            0x04 => { println!("INR B"); pc += 1; }
            0x05 => { println!("DCR B"); pc += 1; }
            0x06 => { print!("MVI B, #${:02x}\n", buf[pc + 1]); pc += 2; }
            0x07 => { println!("RLC"); pc += 1; }
            0x08 => { println!("NOP"); pc += 1; }
            0x09 => { println!("DAD B"); pc += 1; }
            0x0A => { println!("LDAX B"); pc += 1; }
            0x0B => { println!("DCX B"); pc += 1; }
            0x0C => { println!("INR C"); pc += 1;}
            0x0D => { println!("DCR C"); pc += 1; }
            0x0E => { print!("MVI C, #${:02x}\n", buf[pc + 1]); pc += 2; }
            0x0F => { println!("RRC");  pc += 1; }

            0x10 => { println!("NOP"); pc += 1; }
            0x11 => {
                print!("LXI D {}\n", format!("#${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0x12 => { println!("STAX D"); pc += 1; }
            0x13 => { println!("INX D"); pc += 1;}
            0x14 => { println!("INR D"); pc += 1;}
            0x15 => { println!("DCR D"); pc += 1; }
            0x16 => { print!("MVI D, #${:02x}\n", buf[pc + 1]); pc += 2; }
            0x17 => { println!("RAL"); pc += 1;}
            0x18 => { println!("NOP"); pc += 1; }
            0x19 => { println!("DAD D"); pc += 1;}
            0x1A => { println!("LDAX D"); pc += 1; }
            0x1B => { println!("DCX D"); pc += 1;}
            0x1C => { println!("INR E"); pc += 1;}
            0x1D => { println!("DCR E"); pc += 1; }
            0x1E => { print!("MVI E, #${:02x}\n", buf[pc + 1]); pc += 2; }
            0x1F => { println!("RAR"); pc += 1; }

            0x20 => { println!("RIM"); pc += 1; }
            0x21 => {
                print!("LXI H {}\n", format!("#${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0x22 => {
                print!("SHLD {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0x23 => { println!("INX H"); pc += 1;}
            0x24 => { println!("INR H"); pc += 1;}
            0x25 => { println!("DCR H"); pc += 1; }
            0x26 => { print!("MVI H, #${:02x}\n", buf[pc + 1]); pc += 2; }
            0x27 => { println!("DAA"); pc += 1; }
            0x28 => { println!("NOP"); pc += 1; }
            0x29 => { println!("DAD H"); pc += 1; }
            0x2A => {
                print!("LHLD {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0x2B => { println!("DCX H"); pc += 1; }
            0x2C => { println!("INR L"); pc += 1; }
            0x2D => { println!("DCR L"); pc += 1; }
            0x2E => { print!("MVI L, #${:02x}\n", buf[pc + 1]); pc += 2; }
            0x2F => { println!("CMA"); pc += 1;}

            0x30 => { println!("NOP"); pc += 1; } 
            0x31 => {
                print!("LXI SP {}\n", format!("#${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0x32 => {
                print!("STA {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0x33 => { println!("INX SP"); pc += 1;}
            0x34 => { println!("INR M"); pc += 1;}
            0x35 => { println!("DCR M"); pc += 1; }
            0x36 => { print!("MVI M, #${:02x}\n", buf[pc + 1]); pc += 2; }
            0x37 => { print!("STC"); pc += 1; }
            0x38 => { print!("NOP"); pc += 1; }
            0x39 => { println!("DAD SP"); pc += 1; }
            0x3A => {
                print!("LDA {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0x3B => { println!("DCX SP"); pc += 1; }
            0x3C => { println!("INR A"); pc += 1;}
            0x3D => { println!("DCR A"); pc += 1; }
            0x3E => { print!("MVI A, #${:02x}\n", buf[pc + 1]); pc += 2; }
            0x3F => { println!("CMC"); pc += 1; }

            0x40 => { println!("MOV B, B"); pc += 1; }
            0x41 => { println!("MOV B, C"); pc += 1; }
            0x42 => { println!("MOV B, D"); pc += 1; }
            0x43 => { println!("MOV B, E"); pc += 1; }
            0x44 => { println!("MOV B, H"); pc += 1; }
            0x45 => { println!("MOV B, L"); pc += 1; }
            0x46 => { println!("MOV B, M"); pc += 1; }
            0x47 => { println!("MOV B, A"); pc += 1; }
            0x48 => { println!("MOV C, B"); pc += 1; }
            0x49 => { println!("MOV C, C"); pc += 1; }
            0x4A => { println!("MOV C, D"); pc += 1; }
            0x4B => { println!("MOV C, E"); pc += 1; }
            0x4C => { println!("MOV C, H"); pc += 1; }
            0x4D => { println!("MOV C, L"); pc += 1; }
            0x4E => { println!("MOV C, M"); pc += 1; }
            0x4F => { println!("MOV C, A"); pc += 1; }

            0x50 => { println!("MOV D, B"); pc += 1; }
            0x51 => { println!("MOV D, C"); pc += 1; }
            0x52 => { println!("MOV D, D"); pc += 1; }
            0x53 => { println!("MOV D, E"); pc += 1; }
            0x54 => { println!("MOV D, H"); pc += 1; }
            0x55 => { println!("MOV D, L"); pc += 1; }
            0x56 => { println!("MOV D, M"); pc += 1; }
            0x57 => { println!("MOV D, A"); pc += 1; }
            0x58 => { println!("MOV E, B"); pc += 1; }
            0x59 => { println!("MOV E, C"); pc += 1; }
            0x5A => { println!("MOV E, D"); pc += 1; }
            0x5B => { println!("MOV E, E"); pc += 1; }
            0x5C => { println!("MOV E, H"); pc += 1; }
            0x5D => { println!("MOV E, L"); pc += 1; }
            0x5E => { println!("MOV E, M"); pc += 1; }
            0x5F => { println!("MOV E, A"); pc += 1; }
            
            0x60 => { println!("MOV H, B"); pc += 1; }
            0x61 => { println!("MOV H, C"); pc += 1; }
            0x62 => { println!("MOV H, D"); pc += 1; }
            0x63 => { println!("MOV H, E"); pc += 1; }
            0x64 => { println!("MOV H, H"); pc += 1; }
            0x65 => { println!("MOV H, L"); pc += 1; }
            0x66 => { println!("MOV H, M"); pc += 1; }
            0x67 => { println!("MOV H, A"); pc += 1; }
            0x68 => { println!("MOV L, B"); pc += 1; }
            0x69 => { println!("MOV L, C"); pc += 1; }
            0x6A => { println!("MOV L, D"); pc += 1; }
            0x6B => { println!("MOV L, E"); pc += 1; }
            0x6C => { println!("MOV L, H"); pc += 1; }
            0x6D => { println!("MOV L, L"); pc += 1; }
            0x6E => { println!("MOV L, M"); pc += 1; }
            0x6F => { println!("MOV L, A"); pc += 1; }

            0x70 => { println!("MOV M, B"); pc += 1; }
            0x71 => { println!("MOV M, C"); pc += 1; }
            0x72 => { println!("MOV M, D"); pc += 1; }
            0x73 => { println!("MOV M, E"); pc += 1; }
            0x74 => { println!("MOV M, H"); pc += 1; }
            0x75 => { println!("MOV M, L"); pc += 1; }
            0x76 => { println!("HLT"); pc += 1;      }
            0x77 => { println!("MOV M, A"); pc += 1; }
            0x78 => { println!("MOV A, B"); pc += 1; }
            0x79 => { println!("MOV A, C"); pc += 1; }
            0x7A => { println!("MOV A, D"); pc += 1; }
            0x7B => { println!("MOV A, E"); pc += 1; }
            0x7C => { println!("MOV A, H"); pc += 1; }
            0x7D => { println!("MOV A, L"); pc += 1; }
            0x7E => { println!("MOV A, M"); pc += 1; }
            0x7F => { println!("MOV A, A"); pc += 1; }

            0x80 => { println!("ADD B"); pc += 1; }
            0x81 => { println!("ADD C"); pc += 1; }
            0x82 => { println!("ADD D"); pc += 1; }
            0x83 => { println!("ADD E"); pc += 1; }
            0x84 => { println!("ADD H"); pc += 1; }
            0x85 => { println!("ADD L"); pc += 1; }
            0x86 => { println!("ADD M"); pc += 1; }
            0x87 => { println!("ADD A"); pc += 1; }
            0x88 => { println!("ADC B"); pc += 1; }
            0x89 => { println!("ADC C"); pc += 1; }
            0x8A => { println!("ADC D"); pc += 1; }
            0x8B => { println!("ADC E"); pc += 1; }
            0x8C => { println!("ADC H"); pc += 1; }
            0x8D => { println!("ADC L"); pc += 1; }
            0x8E => { println!("ADC M"); pc += 1; }
            0x8F => { println!("ADC A"); pc += 1; }

            0x90 => { println!("SUB B"); pc += 1; }
            0x91 => { println!("SUB C"); pc += 1; }
            0x92 => { println!("SUB D"); pc += 1; }
            0x93 => { println!("SUB E"); pc += 1; }
            0x94 => { println!("SUB H"); pc += 1; }
            0x95 => { println!("SUB L"); pc += 1; }
            0x96 => { println!("SUB M"); pc += 1; }
            0x97 => { println!("SUB A"); pc += 1; }
            0x98 => { println!("SBB B"); pc += 1; }
            0x99 => { println!("SBB C"); pc += 1; }
            0x9A => { println!("SBB D"); pc += 1; }
            0x9B => { println!("SBB E"); pc += 1; }
            0x9C => { println!("SBB H"); pc += 1; }
            0x9D => { println!("SBB L"); pc += 1; }
            0x9E => { println!("SBB M"); pc += 1; }
            0x9F => { println!("SBB A"); pc += 1; }

            0xA0 => { println!("ANA B"); pc += 1; }
            0xA1 => { println!("ANA C"); pc += 1; }
            0xA2 => { println!("ANA D"); pc += 1; }
            0xA3 => { println!("ANA E"); pc += 1; }
            0xA4 => { println!("ANA H"); pc += 1; }
            0xA5 => { println!("ANA L"); pc += 1; }
            0xA6 => { println!("ANA M"); pc += 1; }
            0xA7 => { println!("ANA A"); pc += 1; }
            0xA8 => { println!("XRA B"); pc += 1; }
            0xA9 => { println!("XRA C"); pc += 1; }
            0xAA => { println!("XRA D"); pc += 1; }
            0xAB => { println!("XRA E"); pc += 1; }
            0xAC => { println!("XRA H"); pc += 1; }
            0xAD => { println!("XRA L"); pc += 1; }
            0xAE => { println!("XRA M"); pc += 1; }
            0xAF => { println!("XRA A"); pc += 1; }

            0xB0 => { println!("ORA B"); pc += 1; }
            0xB1 => { println!("ORA C"); pc += 1; }
            0xB2 => { println!("ORA D"); pc += 1; }
            0xB3 => { println!("ORA E"); pc += 1; }
            0xB4 => { println!("ORA H"); pc += 1; }
            0xB5 => { println!("ORA L"); pc += 1; }
            0xB6 => { println!("ORA M"); pc += 1; }
            0xB7 => { println!("ORA A"); pc += 1; }
            0xB8 => { println!("CMP B"); pc += 1; }
            0xB9 => { println!("CMP C"); pc += 1; }
            0xBA => { println!("CMP D"); pc += 1; }
            0xBB => { println!("CMP E"); pc += 1; }
            0xBC => { println!("CMP H"); pc += 1; }
            0xBD => { println!("CMP L"); pc += 1; }
            0xBE => { println!("CMP M"); pc += 1; }
            0xBF => { println!("CMP A"); pc += 1; }

            0xC0 => { println!("RNZ"); pc += 1; }
            0xC1 => { println!("POP B"); pc += 1; }
            0xC2 => {
                print!("JNZ {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xC3 => {
                print!("JMP {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xC4 => {
                print!("CNZ {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xC5 => { println!("PUSH B"); pc += 1; }
            0xC6 => { print!("ADI #${:02x}\n", buf[pc + 1]); pc += 2; }
            0xC7 => { println!("RST 0"); pc += 1; }
            0xC8 => { println!("RZ"); pc += 1; }
            0xC9 => { println!("RET"); pc += 1; }
            0xCA => {
                print!("JZ {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xCB => {
                print!("JMP {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            } 
            0xCC => {
                print!("CZ {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xCD => {
                print!("CALL {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xCE => { print!("ACI #${:02x}\n", buf[pc + 1]); pc += 2; }
            0xCF => { println!("RST 1"); pc += 1; }

            0xD0 => { println!("RNC"); pc += 1; }
            0xD1 => { println!("POP D"); pc += 1; }
            0xD2 => {
                print!("JNC {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xD3 => { print!("OUT #${:02x}\n", buf[pc + 1]); pc += 2; }
            0xD4 => {
                print!("CNC {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xD5 => { println!("PUSH D"); pc += 1; }
            0xD6 => { print!("SUI #${:02x}\n", buf[pc + 1]); pc += 2; }
            0xD7 => { println!("RST 2"); pc += 1; }
            0xD8 => { println!("RC"); pc += 1;}
            0xD9 => { println!("RET"); pc += 1; }
            0xDA => {
                print!("JC {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xDB => { print!("IN #${:02x}\n", buf[pc + 1]); pc += 2; }
            0xDC => {
                print!("CC {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xDD => {
                print!("CALL {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xDE => { print!("SBI #${:02x}\n", buf[pc + 1]); pc += 2; }
            0xDF => { println!("RST 3"); pc += 1; }

            0xE0 => { println!("RPO"); pc += 1; }
            0xE1 => { println!("POP H"); pc += 1; }
            0xE2 => {
                print!("JPO {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xE3 => { println!("XTHL"); pc += 1; }
            0xE4 => {
                print!("CPO {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xE5 => { println!("PUSH H"); pc += 1; }
            0xE6 => { print!("ANI #${:02x}\n", buf[pc + 1]); pc += 2; }
            0xE7 => { println!("RST 4"); pc += 1; }
            0xE8 => { println!("RPE"); pc += 1;}
            0xE9 => { println!("PCHL"); pc += 1;}
            0xEA => {
                print!("JPE {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xEB => { println!("XCHG"); pc += 1; }
            0xEC => {
                print!("CPE {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xED => {
                print!("CALL {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xEE => { print!("XRI #${:02x}\n", buf[pc + 1]); pc += 2; }
            0xEF => { println!("RST 5"); pc += 1; } 

            0xF0 => { println!("RP"); pc += 1; }
            0xF1 => { println!("POP PSW"); pc += 1; }
            0xF2 => {
                print!("JP {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xF3 => { println!("DI"); pc += 1; }
            0xF4 => {
                print!("CP {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xF5 => { println!("PUSH PSW"); pc += 1;}
            0xF6 => { print!("ORI #${:02x}\n", buf[pc + 1]); pc += 2;}
            0xF7 => { println!("RST 6"); pc += 1; }
            0xF8 => { println!("RM"); pc += 1; }
            0xF9 => { println!("SPHL"); pc += 1; }
            0xFA => {
                print!("JM {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xFB => { println!("EI"); pc += 1; }
            0xFC => {
                print!("CM {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xFD => {
                print!("CALL {}\n", format!("${}{}", 
                    format!("{:02x}", buf[pc + 2]),  
                    format!("{:02x}", buf[pc + 1]))
                ); 
                pc += 3;
            }
            0xFE => { print!("CPI #${:02x}\n", buf[pc + 1]); pc += 2; }
            0xFF => { println!("RST 7"); pc += 1; }
        }
    }
}
