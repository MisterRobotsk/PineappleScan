pub mod addfile{
	
	use std::net::{TcpStream, UdpSocket};
	use std::fs::File;
	use std::io::Write;
	use std::time::Instant;
	use chrono::{Datelike, Timelike, Local};
    	use std::process::Command;
    	use dns_lookup::lookup_host;
	
	pub fn print_time(){

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
	
	pub fn scan_tcp(var: String){

	    print!("Starting PineappleScan ({}): ", var);
	    print_time();
            println!("please wait until the program finishes scanning the ports....");
            
	    let start = Instant::now();

	    for port in 1..1024{
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
	
	pub fn scan_udp(var: String){
    
	    print!("Starting PineappleScan ({}): ", var);
	    print_time();
	    println!("please wait until the program finishes scanning the ports....");
	    
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
		        
		        match ip.as_str(){ //tested with localhost
		            "127.0.0.1:7" | "localhost:7" => println!("This port is used by the echo(7) service"),
		            "127.0.0.1:9" | "localhost:9" => println!("This port is used by the discard(9) service"),
		            
		            "127.0.0.1:10" | "localhost:10" => println!("This port is used by the chargen(19) service"),
		            "127.0.0.1:13" | "localhost:13" => println!("This port is used by the DAYTIME"),
		            "127.0.0.1:53" | "localhost:53" => println!("This port is used by the DNS(53) service"),
		            "127.0.0.1:69" | "localhost:69" => println!("This port is used by the TFTP(69)"),
		            
		            "127.0.0.1:111" | "localhost:111" | "127.0.0.1:137" | "localhost:137" | "127.0.0.1:138" |
		                "localhost:138" | "127.0.0.1:139" | "localhost:139"
		                => println!("This port is used by the RPC"),

		            "127.0.0.1:123" | "localhost:123" => println!("This port is used by the NTP(123) service"),
		            "127.0.0.1:161" | "localhost:161" => println!("This port is used by the SNMP(161) servie"),
		            
		            "127.0.0.1:500" | "localhost:500" | "127.0.0.1:1994" | "localhost:1994" | 
		                "127.0.0.1:4500" | "localhost:4500" => println!("This port is used by the VPN service"),
		            
		            "127.0.0.1:2049" | "localhost:2049" => println!("This port is used by the NFS(2049) service"),
		            "127.0.0.1:3391" | "localhost:3391" => println!("This port is used by the RDG(3391) service"),
		            "127.0.0.1:4444" | "localhost:4444" 
		                => println!("This port is used by the tor/proxy(4444) service"),
		            
		            "127.0.0.1:5060" | "localhost:5060" => println!("This port is used by the SIP(5060) service"),

		            _ => continue,
		        }

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
	
	pub fn scan_record_tcp(var: String){

	    let path = "dataTcp.txt";
	    let mut output = File::create(path).unwrap();
	    
	    print!("Starting scan ports ({}): ", var);
	    print_time();
	    println!("please wait until the program finishes scanning the ports....");
	    
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
	
	pub fn scan_record_udp(var: String){

	    let mut count_closed_ports = 0;

	    let path = "dataUdp.txt";
	    let mut output = File::create(path).unwrap();
	    
	    print!("Starting scan ports ({}): ", var);
	    print_time();
	    println!("please wait until the program finishes scanning the ports....");
	    
	    let start = Instant::now();

	    for port in 1..1024{
		let mut ip = String::from(&var);
		ip.push_str(":");
		ip.push_str(&port.to_string());

		if let Ok(socket) = UdpSocket::bind(&ip){
		    
		    if let  Ok(_) = socket.connect(&ip){
		        continue;
		    } else {
		        write!(output, "Port {} is closed.\n", &ip).unwrap();
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

    pub fn scan_ping(var: String){
        
        print!("Starting scan ping port ({}): ", var);
        print_time();
        println!("please wait until the program finishes scanning the ports....");

        let start = Instant::now();

        for port in 1..1024{
            let output = Command::new("ping")
                                .arg("-c")
                                .arg("1")
                                .arg("-w")
                                .arg("1")
                                .arg(&var)
                                .output()
                                .expect("Failed to execute command");
            if output.status.success(){
                continue;
            } else {
                println!("Port {} is closed.", port);
            }
        }
        
        let duration = start.elapsed();
        print!("\nCompleted PineappleScan: ");
        print_time();
        println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}", duration);
    }

    pub fn scan_record_ping(var: String){
        
        let path = "dataPing.txt";
        let mut file_output = File::create(path).unwrap();
    
        print!("Starting scan ping port ({}): ", var);
        print_time();
        println!("please wait until the program finishes scanning the ports....");
        
        let start = Instant::now();

        for port in 1..1024{
            let output = Command::new("ping")
                                .arg("-c")
                                .arg("1")
                                .arg("-w")
                                .arg("1")
                                .arg(&var)
                                .output()
                                .expect("Failed to execute command");

            if output.status.success(){
                continue;
            } else {
                write!(file_output, "Port {} is closed.\n", &port).unwrap();
            }
        }

        let duration = start.elapsed();
        print!("\nCompleted PineappleScan: ");
        print_time();
        println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}", duration);
    }

    pub fn scan_dns(var: String){
        
        print!("Starting search dns ({}): ", var);
        print_time();
        println!("please wait until the program finishes scanning the ports....");
        
        let start = Instant::now();
        
         match lookup_host(&var){
            Ok(ip_addresses) => {
                for ip in ip_addresses{
                    println!("Name:   {}\nAddress: {}", var, ip);
                }
            }, 
            Err(err) => {
                println!("Failed finish work\nName:   {}\nAddress: {}", var, err)
            }
         }
         
         let duration = start.elapsed();
         print!("\nCompleted PineappleScan: ");
         print_time();
         println!("PineappleScan done: 1 IP Address (1 host up) search dns in {:?}", duration);
    }

    pub fn scan_record_dns(var: String){

        let path = String::from("dataDns.txt");
        let mut output = File::create(path).unwrap();

        print!("Starting search dns ({}): ", var);
        print_time();
        println!("please wait until the program finishes scanning the ports....");
        
        let start = Instant::now();

        match lookup_host(&var){
            Ok(ip_addresses) => {
                for ip in ip_addresses{
                    write!(output, "Name:   {}\nAddress: {}\n", var, ip).unwrap();
                }
            },
            Err(err) => {
                println!("Failed finish work\nName:   {}\nAddress: {}", var, err);
            }
        }

        let duration = start.elapsed();
        print!("\nCompleted PineappleScan: ");
        print_time();
        println!("PineappleScan done: 1 IP Address (1 host up) search dns in {:?}", duration);
    }
}
