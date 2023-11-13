# PineappleScan
This repository contains a port scanner written in rust "PineappleScan"

# About
This is a port scanner, so far only 127.0.0.1, in the future there will be 192.168.1.0 and others to scan

# Help with Program:
In order to use program you need clone repository your pc and installed C compiler and Cargo for compiling program. Executable program you find /pineapple_scan/target/debug.
for to launch, run ./pineapple_scan --help for get instruction

# Usage
PineappleScan:

            About program: Scanner port 
            About author: MisterRobotsk
            
            Command:
                -h or --help                print all command program
                -v or --version             print version command
                -sT or --scanTcp            show open ports using TCP scan
                -sU or --scanUdp            
                -sP or --scanPing           shows open ports using ping scan
                -sRP or --scanRecordPing    records open ports using ping scan in f>
                -sRT or --scanRecordTcp     records open ports using TCP scan in fi>
                -sRU or --scanRecordUdp     records open ports using UDP scan in fi>
                -sD or --scanDns            shows the DNS of the host
                -sRD or --scanRecordDns     records the DNS of the host in file
            
            Example:
                -sT 127.0.0.1
                --scanPing example.com
                -sD example.com

                [ARG] <INPUT>
