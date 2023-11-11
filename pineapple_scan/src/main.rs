//функции переместить в отдельный файл и заставить работать программу с многопоточностью

mod args;

use args::addfile::*;

use std::env;

fn main(){
    let help = "\
    Scanner ports:

            About program: Scanner port 
            About author: 
            
            Command:
                -h or --help                print all command program
                -v or --version             print version command
                -sT or --scanTcp            use method tcp for print information about open ports
                -sU or --scanUdp            use method udp for print information about open ports
                -sRT or --scanRecordTcp     record information in file about open ports
                -sRU or --scanRecordUdp     record information in file about free ports

            Example:
                -sT 127.0.0.1
                [ARG] <INPUT>
                ".to_string();


    let args: Vec<String> = env::args().collect();


    if args.len() > 1 {
        let command = &args[1];

        match command.as_str(){
            "-h" | "--help" => println!("{}", help),
            "-v" | "--version" => println!("Version: 0.1"),
            "-sT" | "--scanTcp" => scan_tcp(args[2].to_string()),
            "-sU" | "--scanUdp" => scan_udp(args[2].to_string()),
            "-sRT" | "--scanRecordTcp" => scan_record_tcp(args[2].to_string()),
            "-sRU" | "--scanRecordUdp" => scan_record_udp(args[2].to_string()),
            _ => println!("please use command -h or --help"),
        }
    } else {
        eprintln!("Please try again input, you ");
    }
}

