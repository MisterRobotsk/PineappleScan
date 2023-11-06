use std::env;
use std::net::{TcpStream, UdpSocket};
use std::fs::File;
use std::io::Write;
use std::time::Instant;
use chrono::{Datelike, Timelike, Local};

fn print_time(){

    let now = Local::now();

    let (_, year) = now.year_ce();
    print!(
        "at {}-{:02}-{:02} {:?} ",
        year,
        now.month(),
        now.day(),
        now.weekday(),
    );

    let hour = now.hour();
    let minute = now.minute();
    let second = now.second();
    println!("{:02}:{:02}:{:02}", hour, minute, second);
}

fn scan_tcp(var: String){

    print!("Starting PineappleScan ({}): ", var);
    print_time();

    let start = Instant::now();

    for port in 1..65536{
        let mut ip = String::from(&var);
        ip.push_str(":");
        ip.push_str(&port.to_string());
        
        if let Ok(_) = TcpStream::connect(&ip){
            println!("Port Open: {}", ip);
        }
    }
    let duration = start.elapsed();
    print!("\nCompleted PineappleScan: ");
    print_time();
    println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}", duration);
}

fn scan_udp(var: String){
    
    print!("Starting PineappleScan ({}): ", var);
    print_time();

    let start = Instant::now();
    let mut count_closed_ports = 0;

    for port in 1..1024{
        let mut ip = String::from(&var);
        ip.push_str(":");
        ip.push_str(&port.to_string());

        if let Ok(socket) = UdpSocket::bind(&ip){
            
            if let Ok(_) = socket.connect(&ip){
                continue;
            } else {
                eprintln!("Port closed: {}", ip);
                count_closed_ports += 1;
            }
        }
    }

    if count_closed_ports == 0{ println!("All ports free"); }
    let duration = start.elapsed();
    print!("\nCompleted PineappleScan: ");
    print_time();
    println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}", duration);
}

fn scan_record_tcp(var: String){

    let path = "dataTcp.txt";
    let mut output = File::create(path).unwrap();
    
    print!("Starting scan ports ({}): ", var);
    print_time();

    let start = Instant::now();

    for port in 1..65536{
        let mut ip = String::from(&var);
        ip.push_str(":");
        ip.push_str(&port.to_string());

        if let Ok(_) = TcpStream::connect(&ip){
            write!(output, "Port open: {}\n", &ip).unwrap();
        }
    }
    let duration = start.elapsed();
    print!("\nCompleted PineappleScan: ");
    print_time();
    println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}. Record data in dataTcp.txt", duration);
}

fn scan_record_udp(var: String){

    let mut count_closed_ports = 0;

    let path = "dataUdp.txt";
    let mut output = File::create(path).unwrap();
    
    print!("Starting scan ports ({}): ", var);
    print_time();
    
    let start = Instant::now();

    for port in 1..1024{
        let mut ip = String::from(&var);
        ip.push_str(":");
        ip.push_str(&port.to_string());

        if let Ok(socket) = UdpSocket::bind(&ip){
            
            if let  Ok(_) = socket.connect(&ip){
                continue;
            } else {
                write!(output, "Port closed: {}\n", &ip).unwrap();
                count_closed_ports += 1;
            }
        }
    }
    
    if count_closed_ports == 0{
        write!(output, "All port is free from 1 before 1023").unwrap();
    }
    let duration = start.elapsed();
    print!("\nCompleted PineappleScan: ");
    print_time();
    println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}. Record data in dataUdp.txt", duration);
}

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

