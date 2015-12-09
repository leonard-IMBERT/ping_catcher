extern crate libc;
extern crate socket;
extern crate time;
#[macro_use]
extern crate nom;

use time::Duration;

use socket::{AF_INET, IP_TTL, IPPROTO_IP, SOCK_RAW, SOL_SOCKET, Socket};
use libc::{SO_RCVTIMEO, timeval, time_t, suseconds_t};

use std::io;
use std::fmt;

use nom::{IResult, Needed};

const IPPROTO_ICMP: i32 = 1;

type Word32 = (u8,u8,u8,u8);

struct IcmpMessage{
    icmp_type: u8,
    icmp_code: u8,
    checksum: u16,
    header_content: u32,
    data: Word32,
    optional_data: (Option<Word32>, Option<Word32>),
}

impl fmt::Display for IcmpMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "type: {}\ncode: {}\nchecksum: {}\nheader: {}\ndata: {} {} {} {}",
               self.icmp_type,
               self.icmp_code,
               self.checksum,
               self.header_content,
               self.data.0,
               self.data.1,
               self.data.2,
               self.data.3);
    }
}

fn u8_to_word32(u: &[u8]) -> Option<Word32> {
    named!(scribe(&[u8]) -> Option<Word32>,
    chain!(
            fi: take!(8)    ~
            se: take!(8)    ~
            th: take!(8)    ~
            fo: take!(8)    ,
            || {match (u8_to_u8(fi), u8_to_u8(se), u8_to_u8(th), u8_to_u8(fo)){
                (Some(a), Some(b), Some(c), Some(d)) => Some((a, b, c, d)),
                _ => None,
            }}
            ));
    return match scribe(u){
        IResult::Done(input, output) => output,
        IResult::Error(err) => {
            println!("Error when parsing");
            return None;
        },
        IResult::Incomplete(need) => {
            match need {
                Needed::Unknown => println!("Fuuuuuu"),
                Needed::Size(si) => println!("Missing: {}", si)
            }
            return None;
        }
    };
}

fn u8_point(point: &u8) -> u8 {
    let &ret = point;
    return ret;
}

fn u8_to_u8(table: &[u8]) -> Option<u8> {
    return map_option(table.iter().next(), u8_point);
}

fn u8_to_u16(table: &[u8]) -> Option<u16> {
    let mut iter = table.iter();

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
    let mut iter = table.iter();

    fn as_u32(ei: &u8) -> u32 {
        let &si = ei;
        return si as u32;
    }

    let first_op = map_option(iter.next(), as_u32);
    let secon_op = map_option(iter.next(), as_u32);
    let third_op = map_option(iter.next(), as_u32);
    let fourt_op = map_option(iter.next(), as_u32);

    match (first_op, secon_op, third_op, fourt_op) {
        (Some(fir), Some(sec), Some(thi), Some(fou)) => {
            return Some(
                (fir << (3 * 8)) +
                (sec << (2 * 8)) +
                (thi << 8) +
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

fn convert_data(data: &mut[u8]) -> Option<IcmpMessage> {
    named!(converter(&[u8]) -> Option<IcmpMessage>,
    chain!(
        icmp_t: take!(8)            ~
        icmp_c: take!(8)            ~
        checks: take!(16)           ~
        header_cont: take!(32)      ~
        body: take!(32)             ~
        body1_opt: opt!(take!(32))  ~
        body2_opt: opt!(take!(32))  ,
        || {match (
                u8_to_u8(icmp_t),
                u8_to_u8(icmp_c),
                u8_to_u16(checks),
                u8_to_u32(header_cont),
                u8_to_word32(body),
                ) {
            (Some(ty), Some(co), Some(ch), Some(he), Some(bo)) => Some(IcmpMessage {
                icmp_type:          ty,
                icmp_code:          co,
                checksum:           ch,
                header_content:     he,
                data:               bo,
                optional_data: (
                    flatmap_option(body1_opt, u8_to_word32),
                    flatmap_option(body2_opt, u8_to_word32),
                    )
            }),
            _ => None,
        }}
    )
        );
    return match converter(data){
        IResult::Done(input, output) => output,
        IResult::Error(err) => {
            println!("Error when parsing");
            return None;
        },
        IResult::Incomplete(need) => {
            match need {
                Needed::Unknown => println!("Fuuuuuu"),
                Needed::Size(si) => {
                    print!("input: ");
                    println!("{:?}", data);
                    println!(", Missing: {}", si);
                }
            }
            return None;
        }
    };
}

pub fn listen(dur: Duration) -> io::Result<bool> {
    let mut dataEmpt: [u8; 4096] = [0; 4096];
    let begin = time::get_time();
    let sock = try!(Socket::new(AF_INET, SOCK_RAW, IPPROTO_ICMP));
    while time::get_time() < begin + dur {
        match listen_during(&mut dataEmpt[..], &sock) {
            Ok(data) => match convert_data(data) {
                Some(d) => println!("{}", d),
                None => println!("Error during parsing\n"),
            },
            Err(err) => println!("{}", err),
        }
    }
    return Ok(true);
}

pub fn listen_during<'a>(container: &'a mut [u8], sock: &Socket) -> io::Result<&'a mut [u8]> {
    try!(sock.setsockopt(IPPROTO_IP, IP_TTL, 255));
    try!(sock.setsockopt(SOL_SOCKET, SO_RCVTIMEO, compute_timeout(Duration::seconds(3))));
    match sock.recvfrom_into(container, 0) {
        Err(err) => {
            println!("{}", err);
            return Err(err);
        },
        Ok((s,d)) => {
            println!("{}", "Got ping");
            println!("{:?}", d);
            println!("{}", s);
            return Ok(container);
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
