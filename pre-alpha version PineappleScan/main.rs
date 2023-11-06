use std::net::TcpStream;

fn main(){
    
    println!("░██████╗░█████╗░░█████╗░███╗░░██╗██████╗░░█████╗░██████╗░████████╗");
    println!("██╔════╝██╔══██╗██╔══██╗████╗░██║██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝");
    println!("╚█████╗░██║░░╚═╝███████║██╔██╗██║██████╔╝██║░░██║██████╔╝░░░██║░░░");
    println!("░╚═══██╗██║░░██╗██╔══██║██║╚████║██╔═══╝░██║░░██║██╔══██╗░░░██║░░░");
    println!("██████╔╝╚█████╔╝██║░░██║██║░╚███║██║░░░░░╚█████╔╝██║░░██║░░░██║░░░");
    println!("╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░░░░░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░");

    println!("************************************");
    println!("* /* this is just scanner ports */ *");
    println!("************************************");


    for port in 1..65536{
        
        let mut ip = String::from("127.0.0.1:");
        ip.push_str(&port.to_string());
        
        if let Ok(_stream) = TcpStream::connect(&ip){
            println!("This is port open: {}", ip); 
        }
    }
}
