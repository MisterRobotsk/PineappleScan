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
                
		-sT or --scanTcp            show open ports using TCP connect scan
                -sU or --scanUdp            
                -sP or --scanPing           shows open ports using ping scan
                
		-sRP or --scanRecordPing    records open ports using ping scan in file
                -sRT or --scanRecordTcp     records open ports using TCP connect scan in file
                -sRU or --scanRecordUdp     records open ports using UDP scan in file
                
		-sD or --scanDns            shows the DNS of the host
                -sRD or --scanRecordDns     records the DNS of the host in file
		
		-sLT or --scanListTcp	    scans the list of ports using tcp
		-sLU or --scanListUdp	    scans the list of ports using udp
		-sLP or --scanListPing	    scans the list of ports using ping 
		-sLD or --scnaListDns	    uses the list to show DNS of the host 

		-sLRT or --scanListRecordTcp	scans the list of ports using TCP connect and writes open ports to a file
		-sLRU or --scanListRecordUdp	scans the list of ports using UDP and writes open ports to a file
		-sLRP or --scanListRecordPing	scans the list of ports using Ping and writes open ports to a file
		-sLRD or --scanListRecordDns	using the list writes to a file DNS of the host
            
            Example:
                -sT 127.0.0.1
                --scanPing example.com
                -sD example.com
		-sLU file.txt

                [ARG] <INPUT>
                ".to_string();


    let args: Vec<String> = env::args().collect();


    if args.len() > 1 {
        let command = &args[1];

        match command.as_str(){
            "-h" | "--help" => println!("{}", help),
            "-v" | "--version" => println!("Version: 1.2"),
            
	    "-sT" | "--scanTcp" => scan_tcp(args[2].to_string()),
            "-sU" | "--scanUdp" => scan_udp(args[2].to_string()),
            
	    "-sRT" | "--scanRecordTcp" => scan_record_tcp(args[2].to_string()),
            "-sRU" | "--scanRecordUdp" => scan_record_udp(args[2].to_string()),
            "-sP"  | "--scanPing" => scan_ping(args[2].to_string()),
            
	    "-sRP" | "--scanRecordPing" => scan_record_ping(args[2].to_string()),
            "-sD"  | "--scanDns" => scan_dns(args[2].to_string()),
            "-sRD" | "--scanRecordDns" => scan_record_dns(args[2].to_string()),

	    "-sLT" | "--scanListTcp" => scan_list(args[2].to_string(), "tcp".to_string()),
	    "-sLU" | "--scanListUdp" => scan_list(args[2].to_string(), "udp".to_string()),
	    "-sLP" | "--scanListPing" => scan_list(args[2].to_string(), "ping".to_string()),
	    "-sLD" | "--scanListDns" => scan_list(args[2].to_string(), "dns".to_string()), 
            _ => println!("please use command -h or --help"),
        }
    } else {
        eprintln!("Please enter -h or --help to get help.");
    }
}

