extern crate libc;
extern crate socket;
extern crate time;

use time::Duration;

use socket::{AF_INET, IP_TTL, IPPROTO_IP, SOCK_RAW, SOL_SOCKET, Socket};
use libc::{SO_RCVTIMEO, timeval, time_t, suseconds_t};

use std::io;

const IPPROTO_ICMP: i32 = 1;

pub fn listen(dur: Duration) -> io::Result<bool> {
    let begin = time::get_time();
    let sock = try!(Socket::new(AF_INET, SOCK_RAW, IPPROTO_ICMP));
    while time::get_time() < begin + dur {
        listen_during(&sock);
    }
    return Ok(true);
}

pub fn listen_during(sock: &Socket) -> io::Result<Box<[u8]>> {
    try!(sock.setsockopt(IPPROTO_IP, IP_TTL, 255));
    try!(sock.setsockopt(SOL_SOCKET, SO_RCVTIMEO, compute_timeout(Duration::seconds(3))));
    match sock.recvfrom(4096,0) {
        Err(err) => {
            println!("{}", err);
            return Err(err);
        },
        Ok((s,d)) => {
            println!("{}", "Got ping");
            println!("{}", s);
            for data in d.iter() {
                print!("{} ", data);
            }
            println!("");
            return Ok(d);
        }
    }
}

fn compute_timeout(timeout: Duration) -> timeval {
    let usecs = timeout.num_microseconds().unwrap();
    timeval{ 
        tv_sec: (usecs / 1000000) as time_t,
        tv_usec: (usecs % 1000000) as suseconds_t,
    }
}
