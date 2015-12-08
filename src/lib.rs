extern crate libc;
extern crate socket;
extern crate time;
#[macro_use]
extern crate nom;

use time::Duration;

use socket::{AF_INET, IP_TTL, IPPROTO_IP, SOCK_RAW, SOL_SOCKET, Socket};
use libc::{SO_RCVTIMEO, timeval, time_t, suseconds_t};

use std::io;

use nom::{IResult};

const IPPROTO_ICMP: i32 = 1;

type word32 = (u8,u8,u8,u8);

struct ICMP_MESSAGE{
    icmp_type: u8,
    icmp_code: u8,
    checksum: u16,
    header_content: u32,
    data: word32,
    optional_data: (Option<word32>, Option<word32>),
}

enum PARSING_ERROR {
    NotEnoughByte
}

fn u8_to_word32(u: &[u8]) -> word32 {
    named!(scribe(&[u8]) -> word32, chain!(
        fi: take!(8)    ~
        se: take!(8)    ~
        th: take!(8)    ~
        fo: take!(8)    ,
        || {(fi, se, th, fo)}
    ));
    scribe(u);
}

fn u8_point(point: &u8) -> u8 {
    let &ret = point;
    return ret;
}

fn u8_to_u8(table: &[u8]) -> Option<u8> {
    return map_option(table.iter().next(), u8_point);
}

fn u8_to_u16(table: &[u8]) -> Option<u16> {
    let iter = table.iter();

    fn as_u16(ei: &u8) -> u16 {
        let &si = ei;
        return si as u16;
    }

    let left_op = map_option(iter.next(), as_u16);
    let right_op = map_option(iter.next(), as_u16);
    match (left_op, right_op) {
        (Some(left), Some(right)) => return Some(left << 8 +right),
        _ => return None,
    }
}

fn u8_to_u32(table: &[u8]) -> Option<u32> {
    let iter = table.iter();
    
    fn as_u32(ei: &u8) -> u32 {
        let &si = ei;
        return si as u32;
    }

    let firstOp = map_option(iter.next(), as_u32);
    let seconOp = map_option(iter.next(), as_u32);
    let thirdOp = map_option(iter.next(), as_u32);
    let fourtOp = map_option(iter.next(), as_u32);
    
    match (firstOp, seconOp, thirdOp, fourtOp) {
        (Some(fir), Some(sec), Some(thi), Some(fou)) => {
            return Some(
                fir << (3 * 8) +
                sec << (2 * 8) +
                thi << 8 +
                fou);
        },
        _ => None,
    }
}

fn map_option<A,B>(opt: Option<A>, f: fn(A) -> B) -> Option<B> {
    match opt {
        Some(a) => Some(f(a)),
        None => None,
    }
}

fn flatmap_option<A,B>(opt: Option<A>, f: fn(A) -> Option<B>) -> Option<B> {
    match opt {
        Some(a) => f(a),
        None => None,
    }
}

fn convert_data(data: Box<[u8]>) -> Option<ICMP_MESSAGE> {
    named!(converter(&[u8]) -> Option<ICMP_MESSAGE>,
        chain!(
            icmp_t: take!(8)            ~
            icmp_c: take!(8)            ~
            checks: take!(16)           ~
            header_cont: take!(32)      ~
            body: take!(32)             ~
            body1_opt: opt!(take!(32))  ~
            body2_opt: opt!(take!(32))  ,
            || {
                match (
                    u8_to_u8(icmp_t),
                    u8_to_u8(icmp_c),
                    u8_to_u16(checks),
                    u8_to_u32(header_cont),
                ) {
                    (Some(ty), Some(co), Some(ch), Some(he)) => Some(ICMP_MESSAGE {
                        icmp_type:              ty,
                        icmp_code:              co,
                        checksum:               ch,
                        header_content:         he,
                        data:   u8_to_word32(body),
                        optional_data: (
                            map_option(body1_opt, u8_to_word32),
                            map_option(body2_opt, u8_to_word32),
                        )
                    }),
                    _ => None,
            }}
        )
    );
    let d = Box::into_raw(data);
    Box::from_raw(converter(d))
}

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
