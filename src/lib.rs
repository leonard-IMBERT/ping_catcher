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

use nom::{IResult, be_u8, be_u16};

const IPPROTO_ICMP: i32 = 1;

fn slice_to_ipv4_header(&slice: &[u8; 24]) -> IPv4Header {
    let options = if ((slice[0] << 4) >> 4) < 6 {
        None
    } else {
        Some([slice[20], slice[21], slice[22], slice[23]])
    };
    return IPv4Header {
        version:    slice[0] >> 4,
        ihl:        (slice[0] << 4) >> 4,
        dscp:       slice[1] >> 2,
        ecn:        (slice[1] << 6) >> 6,
        length:     ((slice[2] as u16) << 8) + slice[3] as u16,
        id:         ((slice[4] as u16) << 8) + slice[5] as u16,
        flags:      slice[6] >> 5,
        offset:     ((((slice[6] << 3) >> 3) as u16) << 8) + slice[7] as u16,
        ttl:        slice[8],
        protocol:   slice[9],
        checksum:   ((slice[10] as u16) << 8) + slice[11] as u16,
        source:         [slice[12], slice[13], slice[14], slice[15]],
        destination:    [slice[16], slice[17], slice[18], slice[19]],
        options:        options,
    }
}

pub struct Message {
    header: IPv4Header,
    body: IcmpMessage
}

#[allow(dead_code)]
pub struct IPv4Header {
    version: u8,
    ihl: u8,
    dscp: u8,
    ecn: u8,
    length: u16,
    id: u16,
    flags: u8,
    offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    source: [u8; 4],
    destination: [u8; 4],
    options: Option<[u8; 4]>
}

#[allow(dead_code)]
pub struct IcmpMessage {
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
        let source = self.header.source;
        let dest = self.header.destination;
        return write!(f, "Version: {}\nId: {}\nSource: {}.{}.{}.{}\nDestination: {}.{}.{}.{}\nBody:\n{}",
                      self.header.version,
                      self.header.id,
                      source[0], source[1], source[2], source[3],
                      dest[0], dest[1], dest[2], dest[3],
                      self.body
                      );
    }
}

fn be_array_4(slice: &[u8]) -> Option<[u8; 4]> {
    let mut it = slice.iter();
    return match (it.next(), it.next(), it.next(), it.next()) {
        (Some(&i_0), Some(&i_1), Some(&i_2), Some(&i_3)) => Some([i_0, i_1, i_2, i_3]),
        _ => None,
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
            icmp_t: take!(1)                ~
            icmp_c: take!(1)                ~
            checks: take!(2)                ~
            header_cont: take!(4)           ~
            body1: take!(4)                 ~
            body2: take!(4)                 ~
            body3: take!(4)                 ,
            || {
                match (
                    be_u8(icmp_t),
                    be_u8(icmp_c),
                    be_u16(checks),
                    be_array_4(header_cont),
                    be_array_4(body1),
                    be_array_5(body2),
                    be_array_4(body3)
                ) {
                    (
                        IResult::Done(_, ty),
                        IResult::Done(_, co),
                        IResult::Done(_, ch),
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
                }
            }
    ));

    let mut header: [u8; 24] = [0;24];
    let result = (&mut header[..]).write(&data[..23]);
    let ipv4_header = slice_to_ipv4_header(&mut header);
    return match result {
        Ok(_) => {
            if ipv4_header.ihl > 5 {
                return match converter(&data[24..]){
                    IResult::Done(_, output) => map_option(output,|out| Message {
                        header: slice_to_ipv4_header(&header),
                        body: out,
                    }),
                    IResult::Error(_) => None,
                    IResult::Incomplete(_) => None,
                }
            } else {
                return match converter(&data[20..]){
                    IResult::Done(_, output) => map_option(output,|out| Message {
                        header: slice_to_ipv4_header(&header),
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

pub fn listen_during<'a>(dur: Duration) -> io::Result<Vec<Message>> {
    return listen_during_and(dur, |m| m);
}

pub fn listen_during_and<'a, F, B>(dur: Duration, callback: F) -> io::Result<Vec<B>> where F: Fn(Message) -> B {
    let mut data_empt: [u8; 4096] = [0; 4096];
    let mut result: Vec<B> = Vec::new();
    let begin = time::get_time();
    let sock = try!(Socket::new(AF_INET, SOCK_RAW, IPPROTO_ICMP));

    while time::get_time() < begin + dur {
        match listen(&mut data_empt[..], &sock) {
            Ok(opt) => match opt {
                Some(data) => result.push(callback(data)),
                None => println!("Error during parsing"),
            },
            Err(_) => (),
        }
    }
    return Ok(result);
}

pub fn listen<'a>(container: &'a mut [u8], sock: &Socket) -> io::Result<Option<Message>> {
    try!(sock.setsockopt(IPPROTO_IP, IP_TTL, 255));
    try!(sock.setsockopt(SOL_SOCKET, SO_RCVTIMEO, compute_timeout(Duration::seconds(3))));
    match sock.recvfrom_into(container, 0) {
        Err(err) => {
            return Err(err);
        },
        Ok((_,_)) => {
            return Ok(convert_data(container));
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
