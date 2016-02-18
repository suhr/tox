/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

//! Tests for the DHT module.


use toxcore::binary_io::*;
use toxcore::crypto_core::*;
use toxcore::dht::*;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use ip::IpAddr;
use quickcheck::{Arbitrary, Gen, quickcheck};


/// Safely casts `u64` to 4 `u16`.
fn u64_as_u16s(num: u64) -> (u16, u16, u16, u16) {
    let mut array: [u16; 4] = [0; 4];
    for n in 0..array.len() {
        array[n] = (num >> (16 * n)) as u16;
    }
    (array[0], array[1], array[2], array[3])
}


// PingType::from_bytes()

#[test]
fn ping_type_from_bytes_test() {
    fn random_invalid(bytes: Vec<u8>) {
        if bytes.len() == 0 {
            return;
        } else if bytes[0] == 0 {
            assert_eq!(PingType::Req, PingType::from_bytes(&bytes).unwrap());
        } else if bytes[0] == 1 {
            assert_eq!(PingType::Resp, PingType::from_bytes(&bytes).unwrap());
        } else {
            assert_eq!(None, PingType::from_bytes(&bytes));
        }
    }
    quickcheck(random_invalid as fn(Vec<u8>));

    // just in case
    let p0 = vec![0];
    assert_eq!(PingType::Req, PingType::from_bytes(&p0).unwrap());

    let p1 = vec![1];
    assert_eq!(PingType::Resp, PingType::from_bytes(&p1).unwrap());
}


// Ping::

// ::new()

#[test]
fn ping_new_test() {
    let p1 = Ping::new();
    let p2 = Ping::new();
    assert!(p1 != p2);
    assert!(p1.id != p2.id);
}

// Ping::is_request()

#[test]
fn ping_is_request_test() {
    assert_eq!(true, Ping::new().is_request());
}

// Ping::response()

#[test]
fn ping_response_test() {
    let ping_req = Ping::new();
    let ping_res = ping_req.response().unwrap();
    assert_eq!(ping_req.id, ping_res.id);
    assert_eq!(false, ping_res.is_request());
    assert_eq!(None, ping_res.response());
}

// Ping::as_bytes()

#[test]
fn ping_as_bytes_test() {
    let p = Ping::new();
    let pb = p.as_bytes();
    assert_eq!(PING_SIZE, pb.len());
    // new ping is always a request
    assert_eq!(0, pb[0]);
    let prb = p.response().unwrap().as_bytes();
    // and response is `1`
    assert_eq!(1, prb[0]);
    // `id` of ping should not change
    assert_eq!(pb[1..], prb[1..]);
}

// Ping::from_bytes()

#[test]
fn ping_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() < PING_SIZE || bytes[0] != 0 && bytes[0] != 1 {
            assert_eq!(None, Ping::from_bytes(&bytes));
        } else {
            let p = Ping::from_bytes(&bytes).unwrap();
            // `id` should not differ
            assert_eq!(&u64_to_array(p.id)[..], &bytes[1..9]);

            if bytes[0] == 0 {
                assert_eq!(true, p.is_request());
            } else {
                assert_eq!(false, p.is_request());
            }
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));

    // just in case
    let mut p_req = vec![0];
    p_req.extend_from_slice(&u64_to_array(random_u64()));
    with_bytes(p_req);

    let mut p_resp = vec![1];
    p_resp.extend_from_slice(&u64_to_array(random_u64()));
    with_bytes(p_resp);
}


// IpType::from_bytes()

#[test]
fn ip_type_from_bytes_test() {
    fn with_bytes(bytes: Vec<u8>) {
        if bytes.len() == 0 { return }
        match bytes[0] {
            2   => assert_eq!(IpType::U4, IpType::from_bytes(&bytes).unwrap()),
            10  => assert_eq!(IpType::U6, IpType::from_bytes(&bytes).unwrap()),
            130 => assert_eq!(IpType::T4, IpType::from_bytes(&bytes).unwrap()),
            138 => assert_eq!(IpType::T6, IpType::from_bytes(&bytes).unwrap()),
            _   => assert_eq!(None, IpType::from_bytes(&bytes)),
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));

    // just in case
    with_bytes(vec![0]);
    with_bytes(vec![2]);
    with_bytes(vec![10]);
    with_bytes(vec![130]);
    with_bytes(vec![138]);
}


// IpAddr::as_bytes()

// NOTE: sadly, implementing `Arbitrary` for `IpAddr` doesn't appear to be
// (easily/nicely) dobale, since neither is a part of this crate.

#[test]
fn ip_addr_as_bytes_test() {
    fn with_ipv4(a: u8, b: u8, c: u8, d: u8) {
        let a4 = Ipv4Addr::new(a, b, c, d);
        let ab = IpAddr::V4(a4).as_bytes();
        assert_eq!(4, ab.len());
        assert_eq!(a, ab[0]);
        assert_eq!(b, ab[1]);
        assert_eq!(c, ab[2]);
        assert_eq!(d, ab[3]);
    }
    quickcheck(with_ipv4 as fn(u8, u8, u8, u8));

    fn with_ipv6(n1: u64, n2: u64) {
        let (a, b, c, d) = u64_as_u16s(n1);
        let (e, f, g, h) = u64_as_u16s(n2);
        let a6 = Ipv6Addr::new(a, b, c, d, e, f, g, h);
        let ab = IpAddr::V6(a6).as_bytes();
        assert_eq!(16, ab.len());
        assert_eq!(a, array_to_u16(&[ab[0], ab[1]]));
        assert_eq!(b, array_to_u16(&[ab[2], ab[3]]));
        assert_eq!(c, array_to_u16(&[ab[4], ab[5]]));
        assert_eq!(d, array_to_u16(&[ab[6], ab[7]]));
        assert_eq!(e, array_to_u16(&[ab[8], ab[9]]));
        assert_eq!(f, array_to_u16(&[ab[10], ab[11]]));
        assert_eq!(g, array_to_u16(&[ab[12], ab[13]]));
        assert_eq!(h, array_to_u16(&[ab[14], ab[15]]));
    }
    quickcheck(with_ipv6 as fn(u64, u64));
}


// Ipv6Addr::from_bytes()

#[test]
fn ipv6_addr_from_bytes_test() {
    fn with_bytes(b: Vec<u8>) {
        if b.len() < 16 {
            assert_eq!(None, Ipv6Addr::from_bytes(&b));
        } else {
            let addr = Ipv6Addr::from_bytes(&b).unwrap();
            assert_eq!(&IpAddr::V6(addr).as_bytes()[..16], &b[..16]);
        }
    }
    quickcheck(with_bytes as fn(Vec<u8>));
}


// PackedNode::

impl Arbitrary for PackedNode {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        let udp: bool = g.gen();
        let ipv4: bool = g.gen();

        let mut pk_bytes = [0; PUBLICKEYBYTES];
        g.fill_bytes(&mut pk_bytes);
        let pk = PublicKey::from_slice(&pk_bytes).unwrap();

        if ipv4 {
            let iptype = { if udp { IpType::U4 } else { IpType::T4 }};
            let addr = Ipv4Addr::new(g.gen(), g.gen(), g.gen(), g.gen());
            let saddr = SocketAddrV4::new(addr, g.gen());

            return PackedNode::new(iptype, SocketAddr::V4(saddr), &pk);
        } else {
            let iptype = { if udp { IpType::U6 } else { IpType::T6 }};
            let addr = Ipv6Addr::new(g.gen(), g.gen(), g.gen(), g.gen(),
                                     g.gen(), g.gen(), g.gen(), g.gen());
            let saddr = SocketAddrV6::new(addr, g.gen(), 0, 0);

            return PackedNode::new(iptype, SocketAddr::V6(saddr), &pk);
        }
    }
}

// PackedNode::new()

#[test]
#[allow(non_snake_case)]
// TODO: when `::new()` will be able to fail, this test should check for whether
// it works/fails when needed;
// e.g. `IpType::U4` and supplied `SocketAddr:V6(_)` should fail
fn packed_node_new_test_ip_type_UDP_IPv4() {
    let info = PackedNode::new(IpType::U4,
                               SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());
    assert_eq!(IpType::U4, info.ip_type);
}


// PackedNode::ip()

#[test]
fn packed_node_ip_test() {
    let ipv4 = PackedNode::new(IpType::U4,
                               SocketAddr::V4(SocketAddrV4::from_str("0.0.0.0:0").unwrap()),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    match ipv4.ip() {
        IpAddr::V4(_) => {},
        IpAddr::V6(_) => panic!("This should not have happened, since IPv4 was supplied!"),
    }

    let ipv6 = PackedNode::new(IpType::U6,
                               SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(),
                                   0, 0, 0)),
                               &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap());

    match ipv6.ip() {
        IpAddr::V4(_) => panic!("This should not have happened, since IPv6 was supplied!"),
        IpAddr::V6(_) => {},
    }
}


// PackedNode::as_bytes()

/// Returns all possible variants of `PackedNode` `ip_type`, in order
/// listed by `IpType` enum.
fn packed_node_all_ip_types(saddr: SocketAddr, pk: &PublicKey)
    -> (PackedNode, PackedNode, PackedNode, PackedNode)
{
    let u4 = PackedNode::new(IpType::U4, saddr, pk);
    let u6 = PackedNode::new(IpType::U6, saddr, pk);
    let t4 = PackedNode::new(IpType::T4, saddr, pk);
    let t6 = PackedNode::new(IpType::T6, saddr, pk);
    (u4, u6, t4, t6)
}


#[test]
// tests for various IPv4 – use quickcheck
fn packed_node_as_bytes_test_ipv4() {
    fn with_random_ip(a: u8, b: u8, c: u8, d: u8) {
        let pk = &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();
        let saddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), 1));
        let (u4, _, t4, _) = packed_node_all_ip_types(saddr, pk);
        // check whether ip_type variant matches
        assert!(u4.as_bytes()[0] == 2);
        assert!(t4.as_bytes()[0] == 130);

        // check whether IP matches ..
        //  ..with UDP
        assert!(u4.as_bytes()[1] == a);
        assert!(u4.as_bytes()[2] == b);
        assert!(u4.as_bytes()[3] == c);
        assert!(u4.as_bytes()[4] == d);
        //  ..with TCP
        assert!(t4.as_bytes()[1] == a);
        assert!(t4.as_bytes()[2] == b);
        assert!(t4.as_bytes()[3] == c);
        assert!(t4.as_bytes()[4] == d);

        // check whether length matches
        assert!(u4.as_bytes().len() == PACKED_NODE_IPV4_SIZE);
        assert!(t4.as_bytes().len() == PACKED_NODE_IPV4_SIZE);
    }
    quickcheck(with_random_ip as fn(u8, u8, u8, u8));
}

#[test]
// test for various IPv6 – quickckeck currently doesn't seem to have
// needed functionality, as it would require from quickcheck support for
// more than 4 function arguments
//  - this requires a workaround with loops and hops - i.e. supply to the
//    quickcheck a function that takes 2 `u64` arguments, convert those
//    numbers to arrays, and use numbers from arrays to do the job
fn packed_node_as_bytes_test_ipv6() {
    fn with_random_ip(num1: u64, num2: u64, flowinfo: u32, scope_id: u32) {
        let pk = &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();

        let (a, b, c, d) = u64_as_u16s(num1);
        let (e, f, g, h) = u64_as_u16s(num2);
        let saddr = SocketAddr::V6(
                        SocketAddrV6::new(
                            Ipv6Addr::new(a, b, c, d, e, f, g, h),
                   /*port*/ 1, flowinfo, scope_id));
        let (_, u6, _, t6) = packed_node_all_ip_types(saddr, pk);
        // check whether ip_type variant matches
        assert_eq!(u6.as_bytes()[0], IpType::U6 as u8);
        assert_eq!(t6.as_bytes()[0], IpType::T6 as u8);

        // check whether IP matches ..
        //  ..with UDP
        assert_eq!(&u6.as_bytes()[1..3], &u16_to_array(a)[..]);
        assert_eq!(&u6.as_bytes()[3..5], &u16_to_array(b)[..]);
        assert_eq!(&u6.as_bytes()[5..7], &u16_to_array(c)[..]);
        assert_eq!(&u6.as_bytes()[7..9], &u16_to_array(d)[..]);
        assert_eq!(&u6.as_bytes()[9..11], &u16_to_array(e)[..]);
        assert_eq!(&u6.as_bytes()[11..13], &u16_to_array(f)[..]);
        assert_eq!(&u6.as_bytes()[13..15], &u16_to_array(g)[..]);
        assert_eq!(&u6.as_bytes()[15..17], &u16_to_array(h)[..]);
        //  ..with TCP
        assert_eq!(&t6.as_bytes()[1..3], &u16_to_array(a)[..]);
        assert_eq!(&t6.as_bytes()[3..5], &u16_to_array(b)[..]);
        assert_eq!(&t6.as_bytes()[5..7], &u16_to_array(c)[..]);
        assert_eq!(&t6.as_bytes()[7..9], &u16_to_array(d)[..]);
        assert_eq!(&t6.as_bytes()[9..11], &u16_to_array(e)[..]);
        assert_eq!(&t6.as_bytes()[11..13], &u16_to_array(f)[..]);
        assert_eq!(&t6.as_bytes()[13..15], &u16_to_array(g)[..]);
        assert_eq!(&t6.as_bytes()[15..17], &u16_to_array(h)[..]);

        // check whether length matches
        assert!(u6.as_bytes().len() == PACKED_NODE_IPV6_SIZE);
        assert!(t6.as_bytes().len() == PACKED_NODE_IPV6_SIZE);
    }
    quickcheck(with_random_ip as fn(u64, u64, u32, u32));
}

#[test]
// test serialization of various ports
fn packed_nodes_as_bytes_test_port() {
    fn with_port(port: u16) {
        let pk = &PublicKey::from_slice(&[0; PUBLICKEYBYTES]).unwrap();
        let saddr4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), port));
        let saddr6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(), port, 0, 0));

        let (u4, _, t4, _) = packed_node_all_ip_types(saddr4, pk);
        assert_eq!(&u16_to_array(port)[..], &u4.as_bytes()[5..7]);
        assert_eq!(&u16_to_array(port)[..], &t4.as_bytes()[5..7]);

        // and IPv6
        let (_, u6, _, t6) = packed_node_all_ip_types(saddr6, pk);
        assert_eq!(&u16_to_array(port)[..], &u6.as_bytes()[17..19]);
        assert_eq!(&u16_to_array(port)[..], &t6.as_bytes()[17..19]);

    }
    quickcheck(with_port as fn (u16));
}

#[test]
// test for serialization of random PKs
//  - this requires a workaround with loops and hops - i.e. supply to the
//    quickcheck 4 `u64` arguments, cast to arrays, put elements from arrays
//    into a single vec and use vec to create PK
fn packed_nodes_as_bytes_test_pk() {
    fn with_pk(a: u64, b: u64, c: u64, d: u64) {
        let saddr4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1));
        let saddr6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from_str("::0").unwrap(), 1, 0, 0));

        let mut pk_bytes: Vec<u8> = Vec::with_capacity(PUBLICKEYBYTES);
        pk_bytes.extend_from_slice(&u64_to_array(a));
        pk_bytes.extend_from_slice(&u64_to_array(b));
        pk_bytes.extend_from_slice(&u64_to_array(c));
        pk_bytes.extend_from_slice(&u64_to_array(d));
        let pk_bytes = &pk_bytes[..];

        let pk = &PublicKey::from_slice(pk_bytes).unwrap();

        let (u4, _, t4, _) = packed_node_all_ip_types(saddr4, pk);
        assert_eq!(&u4.as_bytes()[7..], pk_bytes);
        assert_eq!(&t4.as_bytes()[7..], pk_bytes);

        let (_, u6, _, t6) = packed_node_all_ip_types(saddr6, pk);
        assert_eq!(&u6.as_bytes()[19..], pk_bytes);
        assert_eq!(&t6.as_bytes()[19..], pk_bytes);
    }
    quickcheck(with_pk as fn(u64, u64, u64, u64));
}


// PackedNode::from_bytes()

#[test]
fn packed_nodes_from_bytes_test() {
    fn fully_random(pn: PackedNode) {
        assert_eq!(pn, PackedNode::from_bytes(&pn.as_bytes()[..]).unwrap());
    }
    quickcheck(fully_random as fn(PackedNode));
}

#[test]
// test for fail when length is too small
fn packed_nodes_from_bytes_test_length_short() {
    fn fully_random(pn: PackedNode) {
        let pnb = pn.as_bytes();
        assert_eq!(None, PackedNode::from_bytes(&pnb[1..]));
        assert_eq!(None, PackedNode::from_bytes(&pnb[..(pnb.len() - 1)]));
    }
    quickcheck(fully_random as fn(PackedNode));
}

#[test]
// test for fail when length is too big
fn packed_nodes_from_bytes_test_length_too_long() {
    fn fully_random(pn: PackedNode, r_u8: u8) {
        let mut vec = Vec::with_capacity(PACKED_NODE_IPV6_SIZE);
        vec.extend_from_slice(&pn.as_bytes()[..]);
        vec.push(r_u8);
        assert_eq!(None, PackedNode::from_bytes(&vec[..]));
    }
    quickcheck(fully_random as fn(PackedNode, u8));
}

#[test]
// test for fail when first byte is not an `IpType`
fn packed_nodes_from_bytes_test_no_iptype() {
    fn fully_random(pn: PackedNode, r_u8: u8) {
        // not interested in valid options
        if r_u8 == 2 || r_u8 == 10 || r_u8 == 130 || r_u8 == 138 {
            return;
        }
        let mut vec = Vec::with_capacity(PACKED_NODE_IPV6_SIZE);
        vec.push(r_u8);
        vec.extend_from_slice(&pn.as_bytes()[1..]);
        assert_eq!(None, PackedNode::from_bytes(&vec[..]));
    }
    quickcheck(fully_random as fn(PackedNode, u8));
}

#[test]
// test for when `IpType` doesn't match length
fn packed_nodes_from_bytes_test_wrong_iptype() {
    fn fully_random(pn: PackedNode) {
        let mut vec = Vec::with_capacity(PACKED_NODE_IPV6_SIZE);
        match pn.ip_type {
            IpType::U4 => vec.push(IpType::U6 as u8),
            IpType::T4 => vec.push(IpType::T6 as u8),
            IpType::U6 => vec.push(IpType::U4 as u8),
            IpType::T6 => vec.push(IpType::T4 as u8),
        }
        vec.extend_from_slice(&pn.as_bytes()[1..]);
        assert_eq!(None, PackedNode::from_bytes(&vec[..]));
    }
    quickcheck(fully_random as fn(PackedNode));
}