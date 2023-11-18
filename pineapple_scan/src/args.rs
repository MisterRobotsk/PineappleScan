pub mod addfile{
	
	use std::net::{TcpStream, UdpSocket, IpAddr};
	use std::fs::File;
	use std::io::{self, BufRead, Write};
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
	
	pub fn scan_tcp(host: String){

	    print!("Starting PineappleScan ({}): ", host);
	    print_time();
        println!("please wait until the program finishes scanning the ports....");
            
	    let start = Instant::now();

	    	for port in 1..1024{
			let ip: IpAddr = host.parse().expect("Incorrect ip address");
			
			match TcpStream::connect(&(ip, port)){
				Ok(_) => println!("Port open: {}:{}", ip, port),
				Err(_) => continue,
			}
		}

	    let duration = start.elapsed();
	    print!("\nCompleted PineappleScan: ");
	    print_time();
	    println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}", duration);
	}
	
	pub fn scan_udp(host: String){
    
	    print!("Starting PineappleScan ({}): ", host);
	    print_time();
	    println!("please wait until the program finishes scanning the ports....");
	    let start = Instant::now();

        for port in 1..1024{
            let ip: IpAddr = host.parse().expect("Incorrect ip address");

            if let Ok(socket) = UdpSocket::bind(&(ip, port)){
                match socket.connect(&(ip, port)){
                    Ok(_) => println!("Port {}:{} is open", &ip, &port),
                    Err(_) => println!("Port {}:{} is closed", &ip, &port),
                }
            }
        }

	    let duration = start.elapsed();
        print!("\nCompleted PineappleScan: ");
	    print_time();
	    println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}", duration);
	}
	
	pub fn scan_record_tcp(host: String){

	    let path = "dataTcp.txt";
	    let mut output = File::create(path).expect("Please enter name file try again or enter --help");
	    
	    print!("Starting scan ports ({}): ", host);
	    print_time();
	    println!("please wait until the program finishes scanning the ports....");
	    
	    let start = Instant::now();

	    for port in 1..1024{
		let ip: IpAddr = host.parse().expect("Incorrect ip adddress");
	    	
		match TcpStream::connect(&(ip, port)){
			    Ok(_) => write!(output, "Port is open: {}:{}\n", &ip, &port).expect("I don't write data to file, Sorry :("),
			    Err(_) => continue,
		    }
	    }	    

	    let duration = start.elapsed();
	    
        print!("\nCompleted PineappleScan: ");
	    print_time();
	    println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}. Record data in dataTcp.txt", duration);
	}
	
	pub fn scan_record_udp(host: String){

	    let mut count_closed_ports = 0;

	    let path = "dataUdp.txt";
	    let mut output = File::create(path).expect("Please enter name file try again or enter --help");
	    
	    print!("Starting scan ports ({}): ", host);
	    print_time();
	    println!("please wait until the program finishes scanning the ports....");
	    
	    let start = Instant::now();
		
	    for port in 1..1024{
		let ip: IpAddr = host.parse().expect("Incorrect ip address");
		
		if let Ok(socket) = UdpSocket::bind(&(ip, port)){
			match socket.connect(&(ip, port)){
				    Ok(_) => write!(output, "Port {}:{} is open\n", &ip, &port).expect("I don't write data to file, Sorry :("),
				    Err(_) => count_closed_ports += 1,
			    }
		    }
	    }
	    
	    if count_closed_ports == 0{
		    write!(output, "All port is free from 1 before 1023").expect("I don't write data to file, Sorry :(");
	    }

	    let duration = start.elapsed();
	    
        print!("\nCompleted PineappleScan: ");
	    print_time();
	    println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}. Record data in dataUdp.txt", duration);
	}

    pub fn scan_ping(host: String){
        
        print!("Starting scan ping port ({}): ", host);
        print_time();
        println!("please wait until the program finishes scanning the ports....");

        let start = Instant::now();

        for port in 1..1024{
            let output = Command::new("ping")
                                .arg("-c")
                                .arg("1")
                                .arg("-w")
                                .arg("1")
                                .arg(&host)
                                .output()
                                .expect("Failed to execute command");
            if output.status.success(){
                continue;
            } else {
                println!("Port {} is open", port);
            }
        }
        
        let duration = start.elapsed();

        print!("\nCompleted PineappleScan: ");
        print_time();
        println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}", duration);
    }

    pub fn scan_record_ping(host: String){
        
        let path = "dataPing.txt";
        let mut file_output = File::create(path).expect("Please enter name file try again or enter --help");
    
        print!("Starting scan ping port ({}): ", host);
        print_time();
        println!("please wait until the program finishes scanning the ports....");
        
        let start = Instant::now();

        for port in 1..1024{
            let output = Command::new("ping")
                                .arg("-c")
                                .arg("1")
                                .arg("-w")
                                .arg("1")
                                .arg(&host)
                                .output()
                                .expect("Failed to execute command");

            if output.status.success(){
                continue;
            } else {
                write!(file_output, "Port {} is closed.\n", &port).expect("I don't write data to file, Sorry :(");
            }
        }

        let duration = start.elapsed();
        
        print!("\nCompleted PineappleScan: ");
        print_time();
        println!("PineappleScan done: 1 IP Address (1 host up) scanned in {:?}", duration);
    }

    pub fn scan_dns(host: String){
        
        print!("Starting search dns ({}): ", host);
        print_time();
        println!("please wait until the program finishes scanning the ports....");
        
        let start = Instant::now();
        
         match lookup_host(&host){
            Ok(ip_addresses) => {
                for ip in ip_addresses{
                    println!("Name:   {}\nAddress: {}", host, ip);
                }
            }, 
            Err(err) => {
                println!("Not connecting to the server\nName:   {}\nAddress: {}", host, err)
            }
         }
         
         let duration = start.elapsed();

         print!("\nCompleted PineappleScan: ");
         print_time();
         println!("PineappleScan done: 1 IP Address (1 host up) search dns in {:?}", duration);
    }

    pub fn scan_record_dns(host: String){

        let path = String::from("dataDns.txt");
        let mut output = File::create(path).expect("Please enter name file try again or enter --help");

        print!("Starting search dns ({}): ", host);
        print_time();
        println!("please wait until the program finishes scanning the ports....");
        
        let start = Instant::now();

        match lookup_host(&host){
            Ok(ip_addresses) => {
                for ip in ip_addresses{
                    write!(output, "Name:   {}\nAddress: {}\n", host, ip).expect("I don't write data to file, Sorry :(");
                }
            },
            Err(err) => {
                println!("Not connecting to the server\nName:   {}\nAddress: {}", host, err);
            }
        }

        let duration = start.elapsed();
        
        print!("\nCompleted PineappleScan: ");
        print_time();
        println!("PineappleScan done: 1 IP Address (1 host up) search dns in {:?}", duration);
    }

	pub fn scan_list(path: String, choice: String){
		let file = File::open(&path).expect("Please enter name file try again or enter --help");
		let reader = io::BufReader::new(file);
		
		for string in reader.lines(){
			if let Ok(line) = string{

				match choice.as_str(){
					"tcp" => scan_tcp(line),
					"udp" => scan_udp(line),
					"ping" => scan_ping(line),
					"dns" => scan_dns(line),

					"record_tcp" => scan_record_tcp(line),
					"record_udp" => scan_record_udp(line),
					"scan_record_ping" => scan_record_ping(line),
					"scan_record_dns" => scan_record_dns(line),
					_ => println!("nothing!"),
				}
			}
		}
	}
}
