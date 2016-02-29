extern crate libc;
extern crate socket;
extern crate time;
#[macro_use]
extern crate nom;

use time::Duration;

use socket::{AF_INET, IP_TTL, IPPROTO_IP, SOCK_RAW, SOL_SOCKET, Socket};
use libc::{SO_RCVTIMEO, timeval, time_t, suseconds_t};

use std::io;
use std::io::Write;
use std::fmt;

use nom::{IResult, Needed};

const IPPROTO_ICMP: i32 = 1;

trait IPv4Message {
    fn get_version(&self) -> u8;
    fn get_ihl(&self) -> u8;
    fn get_dscp(&self) -> u8;
    fn get_ecn(&self) -> u8;
    fn get_length(&self) -> u16;
    fn get_identification(&self) -> u16;
    fn get_flags(&self) -> u8;
    fn get_offset(&self) -> u16;
    fn get_ttl(&self) -> u8;
    fn get_protocol(&self) -> u8;
    fn get_checksum(&self) -> u16;
    fn get_source_ip(&self) -> [u8; 4];
    fn get_destination_ip(&self) -> [u8; 4];
    fn get_option(&self) -> Option<[u8; 4]>;
}

impl IPv4Message for [u8; 24] {
    fn get_version(&self) -> u8 {
        return self[0] >> 4;
    }
    fn get_ihl(&self) -> u8 {
        return (self[0] << 4) >> 4;
    }
    fn get_dscp(&self) -> u8 {
        return self[1] >> 2;
    }
    fn get_ecn(&self) -> u8 {
        return (self[1] << 6) >> 6;
    }
    fn get_length(&self) -> u16 {
        return ((self[2] as u16) << 8) + self[3] as u16;
    }
    fn get_identification(&self) -> u16 {
        return ((self[4] as u16) << 8) + self[5] as u16;
    }
    fn get_flags(&self) -> u8 {
        return self[6] >> 5;
    }
    fn get_offset(&self) -> u16 {
        return ((((self[6] << 3) >> 3) as u16) << 8) + self[7] as u16;
    }
    fn get_ttl(&self) -> u8 {
        return self[8];
    }
    fn get_protocol(&self) -> u8 {
        return self[9];
    }
    fn get_checksum(&self) -> u16 {
        return ((self[10] as u16) << 8) + self[11] as u16;
    }
    fn get_source_ip(&self) -> [u8; 4] {
        return [self[12], self[13], self[14], self[15]]
    }
    fn get_destination_ip(&self) -> [u8; 4] {
        return [self[16], self[17], self[18], self[19]]
    }
    fn get_option(&self) -> Option<[u8; 4]> {
        if self.get_ihl() <= 5 {
            return None;
        } else {
            return Some([self[20], self[21], self[22], self[23]])
        }
    }
}

struct Message {
    header: [u8; 24],
    body: IcmpMessage
}

struct IcmpMessage{
    icmp_type: u8,
    icmp_code: u8,
    checksum: u16,
    header_content: [u8; 4],
    data1: [u8; 4],
    data2: [u8; 4],
    data3: [u8; 4],
}

impl fmt::Display for IcmpMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        return write!(f, "type: {}\ncode: {}\nchecksum: {}\nheader: {} {} {} {}\ndata:\n{} {} {} {}\n{} {} {} {}\n{} {} {} {}\n",
               self.icmp_type,
               self.icmp_code,
               self.checksum,
               self.header_content[0],self.header_content[1],self.header_content[2],self.header_content[3],
               self.data1[0],self.data1[1],self.data1[2],self.data1[3],
               self.data2[0],self.data2[1],self.data2[2],self.data2[3],
               self.data3[0],self.data3[1],self.data3[2],self.data3[3]
               );
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let source = self.header.get_source_ip();
        let dest = self.header.get_destination_ip();
        return write!(f, "Version: {}\nId: {}\nSource: {}.{}.{}.{}\nDestination: {}.{}.{}.{}\nBody:\n{}",
                      self.header.get_version(),
                      self.header.get_identification(),
                      source[0], source[1], source[2], source[3],
                      dest[0], dest[1], dest[2], dest[3],
                      self.body
                      );
    }
}

fn u8_to_word32(u: &[u8]) -> Option<[u8; 4]> {
    named!(scribe(&[u8]) -> Option<[u8; 4]>,
    chain!(
            fi: take!(8)    ~
            se: take!(8)    ~
            th: take!(8)    ~
            fo: take!(8)    ,
            || {match (u8_to_u8(fi), u8_to_u8(se), u8_to_u8(th), u8_to_u8(fo)){
                (Some(a), Some(b), Some(c), Some(d)) => Some([a,b,c,d]),
                _ => None,
            }}
            ));
    return match scribe(u){
        IResult::Done(_, output) => output,
        IResult::Error(_) => {
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
        (Some(left), Some(right)) => return Some((left << 8) +right),
        _ => return None,
    }
}

fn map_option<A,B,F>(opt: Option<A>, f: F) -> Option<B> where F: Fn(A) -> B {
    match opt {
        Some(a) => Some(f(a)),
        None => None,
    }
}

fn convert_data(data: &mut[u8]) -> Option<Message> {
    named!(
        converter(&[u8]) -> Option<IcmpMessage>,
        chain!(
            icmp_t: take!(8)            ~
            icmp_c: take!(8)            ~
            checks: take!(16)           ~
            header_cont: take!(32)      ~
            body1: take!(32)            ~
            body2: take!(32)            ~
            body3: take!(32)            ,
            || {match(
                    u8_to_u8(icmp_t),
                    u8_to_u8(icmp_c),
                    u8_to_u16(checks),
                    u8_to_word32(header_cont),
                    u8_to_word32(body1),
                    u8_to_word32(body2),
                    u8_to_word32(body3),
                ){(
                    Some(ty),
                    Some(co),
                    Some(ch),
                    Some(he),
                    Some(b1),
                    Some(b2),
                    Some(b3)
                ) => Some(IcmpMessage{
                    icmp_type:          ty,
                    icmp_code:          co,
                    checksum:           ch,
                    header_content:     he,
                    data1:              b1,
                    data2:              b2,
                    data3:              b3,
                }),
                _ => None,
            }}
    ));

    let mut header: [u8; 24] = [0;24];
    let result = (&mut header[..]).write(&data[..23]);
    return match result {
        Ok(_) => {
            if header.get_ihl() > 5 {
                return match converter(&data[24..]){
                    IResult::Done(_, output) => map_option(output,|out| Message {
                        header: header,
                        body: out,
                    }),
                    IResult::Error(_) => None,
                    IResult::Incomplete(_) => None,
                }
            } else {
                return match converter(&data[20..]){
                    IResult::Done(_, output) => map_option(output,|out| Message {
                        header: header,
                        body: out,
                    }),
                    IResult::Error(_) => None,
                    IResult::Incomplete(_) => None,
                }
            };
        },
        Err(_) => None
    }
}

pub fn listen(dur: Duration) -> io::Result<bool> {
    let mut data_empt: [u8; 4096] = [0; 4096];
    let begin = time::get_time();
    let sock = try!(Socket::new(AF_INET, SOCK_RAW, IPPROTO_ICMP));
    while time::get_time() < begin + dur {
        match listen_during(&mut data_empt[..], &sock) {
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
            return Err(err);
        },
        Ok((_,_)) => {
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
