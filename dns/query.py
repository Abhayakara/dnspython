# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Talk to a DNS server using asyncio."""

from __future__ import generators

import errno
import asyncio
import socket
import struct
import sys
import time

import dns.exception
import dns.inet
import dns.name
import dns.message
import dns.rdataclass
import dns.rdatatype

class UnexpectedSource(dns.exception.DNSException):
    """Raised if a query response comes from an unexpected address or port."""
    pass

class BadResponse(dns.exception.FormError):
    """Raised if a query response does not respond to the question asked."""
    pass

def _compute_expiration(timeout):
    if timeout is None:
        return None
    else:
        return time.time() + timeout

def _addresses_equal(af, a1, a2):
    # Convert the first value of the tuple, which is a textual format
    # address into binary form, so that we are not confused by different
    # textual representations of the same address
    n1 = dns.inet.inet_pton(af, a1[0])
    n2 = dns.inet.inet_pton(af, a2[0])
    return n1 == n2 and a1[1:] == a2[1:]

def _destination_and_source(af, where, port, source, source_port):
    # Apply defaults and compute destination and source tuples
    # suitable for use in connect(), sendto(), or bind().
    if af is None:
        try:
            af = dns.inet.af_for_address(where)
        except:
            af = dns.inet.AF_INET
    if af == dns.inet.AF_INET:
        destination = (where, port)
        if source is not None or source_port != 0:
            if source is None:
                source = '0.0.0.0'
            source = (source, source_port)
    elif af == dns.inet.AF_INET6:
        destination = (where, port, 0, 0)
        if source is not None or source_port != 0:
            if source is None:
                source = '::'
            source = (source, source_port, 0, 0)
    return (af, destination, source)

# figure out how much time is left, returning that time in seconds;
# throwing an exception of the expiration time has already passed.
# return None if Expiration is None.
def time_remaining(expiration):
    if expiration != None:
        fto = expiration - time.time()
        if fto <= 0:
            raise dns.exception.Timeout
        return fto
    return None

# Send a datagram on a socket, running any other pending coroutines while
# we wait.   Hides the coroutine dispatch loop, since dnspython only ever
# one I/O operation at a time.
#
# Modeled after sock_recv()/_sock_recv() in selector_events.py in the
# asyncio module.
#
# Note to self: the way this is working, assuming I grok it accurately, is
# that we are creating a future, which wraps a callback so it can be run
# on an event loop.   We then call the callback, passing it the future and
# the arguments.   The callback attempts to send the datagram synchronously;
# if it succeed, it sets a result on the future, which means that when the
# caller waits on the future, the wait will return immediately.   If that
# fails, then the callback registers itself to be called when the descriptor
# is ready to write.   At that point the callback is called, sets the result
# on the future, and that allows the call to asyncio.wait_for() to complete.

@asyncio.coroutine
def asendto(sock, data, dest, expiration):
    loop = asyncio.get_event_loop()
    fut = asyncio.futures.Future(loop=loop)
    timeout = time_remaining(expiration)
    asendto_callback(fut, loop, False, sock, data, dest)
    return asyncio.wait_for(fut, timeout)

def asendto_callback(fut, loop, registered, sock, data, dest):
    fd = sock.fileno()
    if registered:
        loop.remove_writer(fd)
    if fut.cancelled():
        return
    try:
        count = sock.sendto(data, dest)
    except (BlockingIOError, InterruptedError):
        loop.add_writer(fd, asendto_callback, fut, loop, True,
                        sock, data, dest)
    except Exception as e:
        fut.set_exception(e)
    else:
        fut.set_result(count)
    
@asyncio.coroutine
def arecvfrom(sock, limit, expiration):
    loop = asyncio.get_event_loop()
    fut = asyncio.futures.Future(loop=loop)
    timeout = time_remaining(expiration)
    arecvfrom_callback(fut, loop, False, sock, limit)
    return asyncio.wait_for(fut, timeout)

def arecvfrom_callback(fut, loop, registered, sock, limit):
    fd = sock.fileno()
    if registered:
        loop.remove_reader(fd)
    if fut.cancelled():
        return
    try:
        data, sender = sock.recvfrom(limit)
    except (BlockingIOError, InterruptedError):
        loop.add_reader(fd, arecvfrom_callback, fut, loop, True,
                        sock, limit)
    except Exception as e:
        fut.set_exception(e)
    else:
        fut.set_result((data, sender))

@asyncio.coroutine
def udp(q, where, timeout=None, port=53, af=None, source=None, source_port=0,
        ignore_unexpected=False, one_rr_per_rrset=False):
    """Return the response obtained after sending a query via UDP.

    @param q: the query
    @type q: dns.message.Message
    @param where: where to send the message
    @type where: string containing an IPv4 or IPv6 address
    @param timeout: The number of seconds to wait before the query times out.
    If None, the default, wait forever.
    @type timeout: float
    @param port: The port to which to send the message.  The default is 53.
    @type port: int
    @param af: the address family to use.  The default is None, which
    causes the address family to use to be inferred from the form of of where.
    If the inference attempt fails, AF_INET is used.
    @type af: int
    @rtype: dns.message.Message object
    @param source: source address.  The default is the wildcard address.
    @type source: string
    @param source_port: The port from which to send the message.
    The default is 0.
    @type source_port: int
    @param ignore_unexpected: If True, ignore responses from unexpected
    sources.  The default is False.
    @type ignore_unexpected: bool
    @param one_rr_per_rrset: Put each RR into its own RRset
    @type one_rr_per_rrset: bool
    """

    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port, source,
                                                        source_port)
    s = socket.socket(af, socket.SOCK_DGRAM, 0)
    try:
        s.setblocking(False)
        expiration = _compute_expiration(timeout)
        if source is not None:
            s.bind(source)

        yield from asendto(s, wire, destination, expiration)
        
        while 1:
            (wire, from_address) = yield from arecvfrom(s, 65535, expiration)

            if _addresses_equal(af, from_address, destination) or \
                    (dns.inet.is_multicast(where) and \
                         from_address[1:] == destination[1:]):
                break
            if not ignore_unexpected:
                raise UnexpectedSource('got a response from '
                                       '%s instead of %s' % (from_address,
                                                             destination))
    except asyncio.TimeoutError:
        raise dns.exception.Timeout
    except:
        raise
    finally:
        s.close()
    r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                              one_rr_per_rrset=one_rr_per_rrset)
    if not q.is_response(r):
        raise BadResponse
    return r

@asyncio.coroutine
def _net_read(sock, count, expiration):
    """Read the specified number of bytes from sock.  Keep trying until we
    either get the desired amount, or we hit EOF.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    s = b''
    loop = asyncio.get_event_loop()
    while count > 0:
        timeout = time_remaining(expiration)
        co = loop.sock_recv(s, count)
        n = yield from asyncio.wait_for(co, timeout)
        if n == b'':
            raise EOFError
        count = count - len(n)
        s = s + n
    return s

@asyncio.coroutine
def _net_write(s, data, expiration):
    """Write the specified data to the socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    loop = asyncio.get_event_loop()
    timeout = time_remaining(expiration)
    co = loop.sock_sendall(s, data)
    return asyncio.wait_for(co, timeout)

@asyncio.coroutine
def _connect(s, address, expiration):
    """Connect to the specified socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    loop = asyncio.get_event_loop()
    timeout = time_remaining(expiration)
    co = loop.sock_connect(s, address)
    return asyncio.wait_for(co, timeout)

@asyncio.coroutine
def tcp(q, where, timeout=None, port=53, af=None, source=None, source_port=0,
        one_rr_per_rrset=False):
    """Return the response obtained after sending a query via TCP.

    @param q: the query
    @type q: dns.message.Message object
    @param where: where to send the message
    @type where: string containing an IPv4 or IPv6 address
    @param timeout: The number of seconds to wait before the query times out.
    If None, the default, wait forever.
    @type timeout: float
    @param port: The port to which to send the message.  The default is 53.
    @type port: int
    @param af: the address family to use.  The default is None, which
    causes the address family to use to be inferred from the form of of where.
    If the inference attempt fails, AF_INET is used.
    @type af: int
    @rtype: dns.message.Message object
    @param source: source address.  The default is the wildcard address.
    @type source: string
    @param source_port: The port from which to send the message.
    The default is 0.
    @type source_port: int
    @param one_rr_per_rrset: Put each RR into its own RRset
    @type one_rr_per_rrset: bool
    """

    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port, source,
                                                        source_port)
    s = socket.socket(af, socket.SOCK_STREAM, 0)
    try:
        expiration = _compute_expiration(timeout)
        s.setblocking(0)
        if source is not None:
            s.bind(source)
        yield from _connect(s, destination, expiration)

        l = len(wire)

        # copying the wire into tcpmsg is inefficient, but lets us
        # avoid writev() or doing a short write that would get pushed
        # onto the net
        tcpmsg = struct.pack("!H", l) + wire
        yield from _net_write(s, tcpmsg, expiration)
        ldata = yield from _net_read(s, 2, expiration)
        (l,) = struct.unpack("!H", ldata)
        wire = yield from _net_read(s, l, expiration)
    except asyncio.TimeoutError:
        raise dns.exception.Timeout
    except:
        raise
    finally:
        s.close()
    r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                              one_rr_per_rrset=one_rr_per_rrset)
    if not q.is_response(r):
        raise BadResponse
    return r

@asyncio.coroutine
def xfr(where, zone, rdtype=dns.rdatatype.AXFR, rdclass=dns.rdataclass.IN,
        timeout=None, port=53, keyring=None, keyname=None, relativize=True,
        af=None, lifetime=None, source=None, source_port=0, serial=0,
        use_udp=False, keyalgorithm=dns.tsig.default_algorithm):
    """Return a generator for the responses to a zone transfer.

    @param where: where to send the message
    @type where: string containing an IPv4 or IPv6 address
    @param zone: The name of the zone to transfer
    @type zone: dns.name.Name object or string
    @param rdtype: The type of zone transfer.  The default is
    dns.rdatatype.AXFR.
    @type rdtype: int or string
    @param rdclass: The class of the zone transfer.  The default is
    dns.rdataclass.IN.
    @type rdclass: int or string
    @param timeout: The number of seconds to wait for each response message.
    If None, the default, wait forever.
    @type timeout: float
    @param port: The port to which to send the message.  The default is 53.
    @type port: int
    @param keyring: The TSIG keyring to use
    @type keyring: dict
    @param keyname: The name of the TSIG key to use
    @type keyname: dns.name.Name object or string
    @param relativize: If True, all names in the zone will be relativized to
    the zone origin.  It is essential that the relativize setting matches
    the one specified to dns.zone.from_xfr().
    @type relativize: bool
    @param af: the address family to use.  The default is None, which
    causes the address family to use to be inferred from the form of of where.
    If the inference attempt fails, AF_INET is used.
    @type af: int
    @param lifetime: The total number of seconds to spend doing the transfer.
    If None, the default, then there is no limit on the time the transfer may
    take.
    @type lifetime: float
    @rtype: generator of dns.message.Message objects.
    @param source: source address.  The default is the wildcard address.
    @type source: string
    @param source_port: The port from which to send the message.
    The default is 0.
    @type source_port: int
    @param serial: The SOA serial number to use as the base for an IXFR diff
    sequence (only meaningful if rdtype == dns.rdatatype.IXFR).
    @type serial: int
    @param use_udp: Use UDP (only meaningful for IXFR)
    @type use_udp: bool
    @param keyalgorithm: The TSIG algorithm to use; defaults to
    dns.tsig.default_algorithm
    @type keyalgorithm: string
    """

    if isinstance(zone, str):
        zone = dns.name.from_text(zone)
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)
    q = dns.message.make_query(zone, rdtype, rdclass)
    if rdtype == dns.rdatatype.IXFR:
        rrset = dns.rrset.from_text(zone, 0, 'IN', 'SOA',
                                    '. . %u 0 0 0 0' % serial)
        q.authority.append(rrset)
    if not keyring is None:
        q.use_tsig(keyring, keyname, algorithm=keyalgorithm)
    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port, source,
                                                        source_port)
    if use_udp:
        if rdtype != dns.rdatatype.IXFR:
            raise ValueError('cannot do a UDP AXFR')
        s = socket.socket(af, socket.SOCK_DGRAM, 0)
    else:
        s = socket.socket(af, socket.SOCK_STREAM, 0)
    s.setblocking(0)
    if source is not None:
        s.bind(source)
    expiration = _compute_expiration(lifetime)
    try:
        yield from _connect(s, destination, expiration)
    except asyncio.TimeoutError:
        raise dns.exception.Timeout
    except:
        raise
    l = len(wire)
    if use_udp:
        yield from _net_write(s, wire, expiration)
    else:
        tcpmsg = struct.pack("!H", l) + wire
        yield from _net_write(s, tcpmsg, expiration)
    done = False
    delete_mode = True
    expecting_SOA = False
    soa_rrset = None
    soa_count = 0
    if relativize:
        origin = zone
        oname = dns.name.empty
    else:
        origin = None
        oname = zone
    tsig_ctx = None
    first = True
    while not done:
        mexpiration = _compute_expiration(timeout)
        if mexpiration is None or mexpiration > expiration:
            mexpiration = expiration
        try:
            if use_udp:
                (wire, from_address) = yield from arecvfrom(s, 65535, expiration)
            else:
                ldata = yield from _net_read(s, 2, mexpiration)
                (l,) = struct.unpack("!H", ldata)
                wire = yield from _net_read(s, l, mexpiration)
        except asyncio.TimeoutError:
            raise dns.exception.Timeout
        except:
            raise
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  xfr=True, origin=origin, tsig_ctx=tsig_ctx,
                                  multi=True, first=first,
                                  one_rr_per_rrset=(rdtype==dns.rdatatype.IXFR))
        tsig_ctx = r.tsig_ctx
        first = False
        answer_index = 0
        if soa_rrset is None:
            if not r.answer or r.answer[0].name != oname:
                raise dns.exception.FormError("No answer or RRset not for qname")
            rrset = r.answer[0]
            if rrset.rdtype != dns.rdatatype.SOA:
                raise dns.exception.FormError("first RRset is not an SOA")
            answer_index = 1
            soa_rrset = rrset.copy()
            if rdtype == dns.rdatatype.IXFR:
                if soa_rrset[0].serial <= serial:
                    #
                    # We're already up-to-date.
                    #
                    done = True
                else:
                    expecting_SOA = True
        #
        # Process SOAs in the answer section (other than the initial
        # SOA in the first message).
        #
        for rrset in r.answer[answer_index:]:
            if done:
                raise dns.exception.FormError("answers after final SOA")
            if rrset.rdtype == dns.rdatatype.SOA and rrset.name == oname:
                if expecting_SOA:
                    if rrset[0].serial != serial:
                        raise dns.exception.FormError("IXFR base serial mismatch")
                    expecting_SOA = False
                elif rdtype == dns.rdatatype.IXFR:
                    delete_mode = not delete_mode
                #
                # If this SOA RRset is equal to the first we saw then we're
                # finished. If this is an IXFR we also check that we're seeing
                # the record in the expected part of the response.
                #
                if rrset == soa_rrset and \
                        (rdtype == dns.rdatatype.AXFR or \
                        (rdtype == dns.rdatatype.IXFR and delete_mode)):
                    done = True
            elif expecting_SOA:
                #
                # We made an IXFR request and are expecting another
                # SOA RR, but saw something else, so this must be an
                # AXFR response.
                #
                rdtype = dns.rdatatype.AXFR
                expecting_SOA = False
        if done and q.keyring and not r.had_tsig:
            raise dns.exception.FormError("missing TSIG")
        yield r
    s.close()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    s.setblocking(False)
    # Send a query to the local resolver.
    n = dns.name.from_text("www.dnspython.org")
    request = dns.message.make_query(n, dns.rdatatype.A, dns.rdataclass.IN)
    expiration = _compute_expiration(10)
    co = asendto(s, request.to_wire(), ("127.0.0.1", 53), expiration)
    loop.run_until_complete(co)
    co = arecvfrom(s, 65535, expiration)
    (wire, from_address) = loop.run_until_complete(co)
    result = dns.message.from_wire(wire)
    print(repr(result))
