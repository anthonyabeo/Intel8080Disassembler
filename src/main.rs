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

    let mut f = match File::open(Path::new("invaders")) {
        Ok(file) => file,
        Err(e) => {
            println!("{}", e.description());
            process::exit(1);
        }
    };
    
    let size = f.metadata().unwrap().len() as usize;

    let mut buf = vec![0_u8; size];
    f.read(&mut buf).unwrap();

    println!("{:?}", buf);
}
