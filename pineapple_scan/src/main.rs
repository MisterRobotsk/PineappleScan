mod args;

use args::addfile::*;
use std::env;

fn main(){
    let help = "\
    PineappleScan:

            About program: Scanner port 
            About author: MisterRobotsk
            
            Command:
                -h or --help                print all command program
                -v or --version             print version command
                -sT or --scanTcp            show open ports using TCP scan
                -sU or --scanUdp            
                -sP or --scanPing           shows open ports using ping scan
                -sRP or --scanRecordPing    records open ports using ping scan in file
                -sRT or --scanRecordTcp     records open ports using TCP scan in file
                -sRU or --scanRecordUdp     records open ports using UDP scan in file
                -sD or --scanDns            shows the DNS of the host
                -sRD or --scanRecordDns     records the DNS of the host in file
            
            Example:
                -sT 127.0.0.1
                --scanPing example.com
                -sD example.com

                [ARG] <INPUT>
                ".to_string();


    let args: Vec<String> = env::args().collect();


    if args.len() > 1 {
        let command = &args[1];

        match command.as_str(){
            "-h" | "--help" => println!("{}", help),
            "-v" | "--version" => println!("Version: 1.0"),
            "-sT" | "--scanTcp" => scan_tcp(args[2].to_string()),
            "-sU" | "--scanUdp" => scan_udp(args[2].to_string()),
            "-sRT" | "--scanRecordTcp" => scan_record_tcp(args[2].to_string()),
            "-sRU" | "--scanRecordUdp" => scan_record_udp(args[2].to_string()),
            "-sP" | "--scanPing" => scan_ping(args[2].to_string()),
            "-sRP" | "--scanRecordPing" => scan_record_ping(args[2].to_string()),
            "-sD" | "--scanDns" => scan_dns(args[2].to_string()),
            "-sRD" | "--scanRecordDns" => scan_record_dns(args[2].to_string()),
            _ => println!("please use command -h or --help"),
        }
    } else {
        eprintln!("Please enter -h or --help to get help.");
    }
}

