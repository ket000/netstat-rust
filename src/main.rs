use netstat2::*;
use sysinfo::System;

struct ProcessInfo {
    pid: u32,
    name: String,
}

struct SocketInfo {
    processes: Vec<ProcessInfo>,
    local_port: u16,
    local_addr: std::net::IpAddr,
    remote_port: Option<u16>,
    remote_addr: Option<std::net::IpAddr>,
    protocol: ProtocolFlags,
    state: Option<TcpState>,
    family: AddressFamilyFlags,
}

fn main() {
    let mut sys = System::new_all();
    // sys.refresh_processes(sysinfo::ProcessRefreshKind::everything(), sysinfo::RefreshKind::new());
    //sys.refresh_processes(sysinfo::ProcessRefreshKind::everything(), true);
      sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    
    let mut sockets = get_sockets(&sys, AddressFamilyFlags::IPV4);
    let mut sockets6 = get_sockets(&sys, AddressFamilyFlags::IPV6);
    sockets.append(&mut sockets6);
    
    sockets.sort_by(|a, b| a.local_port.cmp(&b.local_port));
    
    println!("------------------------------");
    println!("TCP socket information");
    println!("------------------------------");
    print_tcp(&sockets);
    
    println!();
    println!("------------------------------");
    println!("UDP socket information");
    println!("------------------------------");
    print_udp(&sockets);
}

fn print_tcp(sockets: &[SocketInfo]) {
    for s in sockets {
        if s.protocol != ProtocolFlags::TCP {
            continue;
        }

        let ip_ver = if s.family == AddressFamilyFlags::IPV4 { "4" } else { "6" };
        let state_str = s.state.map_or("UNKNOWN".to_string(), |st| format!("{:?}", st));
        let process_info = s.processes.get(0).map_or("Unknown Process".to_string(), |p| format!("{} ({})", p.name, p.pid));

        if s.state == Some(TcpState::Listen) {
            println!(
                "TCP{} {:>30}:{:<5}    {:<30} [{}]",
                ip_ver, s.local_addr, s.local_port, process_info, state_str
            );
        } else {
            println!(
                "TCP{} {:>30}:{:<5} -> {:>6}:{:<30} [{}]",
                ip_ver, s.local_addr, s.local_port, s.remote_port.unwrap_or(0), s.remote_addr.map_or("-".to_string(), |a| a.to_string()), state_str
            );
        }
    }
}

fn print_udp(sockets: &[SocketInfo]) {
    for s in sockets {
        if s.protocol != ProtocolFlags::UDP {
            continue;
        }

        let ip_ver = if s.family == AddressFamilyFlags::IPV4 { "4" } else { "6" };
        let process_info = s.processes.get(0).map_or("Unknown Process".to_string(), |p| format!("{} ({})", p.name, p.pid));

        println!("UDP{} {:>30}:{:<8} {}", ip_ver, s.local_addr, s.local_port, process_info);
    }
}

fn get_sockets(sys: &System, addr: AddressFamilyFlags) -> Vec<SocketInfo> {
    let protos = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let iterator = iterate_sockets_info(addr, protos).expect("Failed to get socket information!");
    
    let mut sockets: Vec<SocketInfo> = Vec::new();
    
    for info in iterator {
        let si = match info {
            Ok(si) => si,
            Err(_) => {
                println!("Failed to get info for socket!");
                continue;
            }
        };
    
        let processes: Vec<ProcessInfo> = si.associated_pids.iter().map(|&pid| {
            let pid_obj = sysinfo::Pid::from_u32(pid);
            let name = sys.process(pid_obj)
                .map_or("".to_string(), |p| p.name().to_string_lossy().into_owned());
            ProcessInfo { pid, name }
        }).collect();
    
        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => sockets.push(SocketInfo {
                processes,
                local_port: tcp.local_port,
                local_addr: tcp.local_addr,
                remote_port: Some(tcp.remote_port),
                remote_addr: Some(tcp.remote_addr),
                protocol: ProtocolFlags::TCP,
                state: Some(tcp.state),
                family: addr,
            }),
            ProtocolSocketInfo::Udp(udp) => sockets.push(SocketInfo {
                processes,
                local_port: udp.local_port,
                local_addr: udp.local_addr,
                remote_port: None,
                remote_addr: None,
                state: None,
                protocol: ProtocolFlags::UDP,
                family: addr,
            }),
        }
    }

    sockets
}
