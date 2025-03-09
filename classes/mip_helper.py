# The MIT License (MIT)
#
# Copyright (C) 2016 Michal Kosciesza <michal@mkiol.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""Mobile IP implementation.

RFC 5944 implementation of the Mobile IP protocol, Home Agent and
Mobile Node Agent for Linux.
"""

import struct
import socket
import time
import hmac
import logging
import threading
import os
import sys

from ntplib import _to_int as timestamp_to_int
from ntplib import _to_frac as timestamp_to_frac
from ntplib import _to_time as timestamp_to_time
from ntplib import system_to_ntp_time
from pyroute2 import IPRoute
from netaddr import IPAddress, IPNetwork


INFINITE_LIFETIME = 65535

_ipr = IPRoute()

if not hasattr(socket,'SO_BINDTODEVICE') :
    socket.SO_BINDTODEVICE = 25


def get_ifname(address):
    """Search the interface with given IP address and return
    tuple: interface name and subnet prefix lenght."""
    
    ifname = None
    prefixlen = None
    addr_list = _ipr.get_addr(address=address)
    if len(addr_list) > 0:
        ifname = addr_list[0].get_attr("IFA_LABEL")
        prefixlen = addr_list[0]["prefixlen"]
    return (ifname, prefixlen)


def get_address(ifname):
    """Search the interface with given name and return
    tuple: interface IP address and subnet prefix lenght."""

    address = None
    prefixlen = None
    addr_list = _ipr.get_addr(label=ifname)
    if len(addr_list) > 0:
        address = addr_list[0].get_attr("IFA_ADDRESS")
        prefixlen = addr_list[0]["prefixlen"]
    return (address, prefixlen)


def get_interfaces_states(interfaces=None):
    """Return dict with state ("UP" or "DOWN") of network interfaces.
    Interface is considered as "UP" if IP address is assigned."""

    states = {}
    links = _ipr.get_links()
    for link in links:
        ifname = link.get_attr("IFLA_IFNAME")
        if interfaces is None or ifname in interfaces:
            ip_list = _ipr.get_addr(family=socket.AF_INET, label=ifname)
            if len(ip_list) > 0:
                state = "UP"
            else:
                state = "DOWN"
            states[ifname] = state
    return states


def _get_default_gw():
    """Return tuple (IP address, interface name, metric) that describes
    default gateway configured in the OS."""

    dr_list = _ipr.get_default_routes(family=socket.AF_INET)
    if len(dr_list) > 0:
        ip = dr_list[0].get_attr("RTA_GATEWAY")
        oif = dr_list[0].get_attr("RTA_OIF")
        met = dr_list[0].get_attr("RTA_PRIORITY")
        ifname = _ipr.get_links(oif)[0].get_attr("IFLA_IFNAME")
        return (ip, ifname, met)
    return (None, None, None)


def _get_default_gws():
    """Return list of tuples (IP address, interface name, metric) that
    describes default gateways configured in the OS."""

    result = []
    dr_list = _ipr.get_default_routes(family=socket.AF_INET)
    for dr in dr_list:
        ip = dr.get_attr("RTA_GATEWAY")
        oif = dr.get_attr("RTA_OIF")
        met = dr.get_attr("RTA_PRIORITY")
        ifname = _ipr.get_links(oif)[0].get_attr("IFLA_IFNAME")
        result.append((ip, ifname, met))
    return result


def is_address_in_subnet(address, network):
    """Return True if given IP address belongs to given network."""

    if IPAddress(address) in IPNetwork(network):
        return True
    return False


def is_address_reachable(address):
    """Return True if given IP address belongs to any network configured
    on the OS interfaces."""

    links = _ipr.get_links()
    for link in links:
        ifname = link.get_attr("IFLA_IFNAME")
        list = _ipr.get_addr(family=socket.AF_INET, label=ifname)
        for ipo in list:
            ifaddress = ipo.get_attr("IFA_ADDRESS")
            ifprefixlen = ipo["prefixlen"]
            #logging.debug("address: %s, network: %s/%s", address, ifaddress, ifprefixlen)
            if (ifprefixlen > 0 and
                is_address_in_subnet(address, "%s/%s"%(ifaddress, ifprefixlen))):
                return True
    return False


def _is_route_exists(dst):
    """Return True if destination (IP address/network prefix length,
    e.g. "10.1.0.1/30") belongs to any network configured
    on the OS interfaces."""

    route_list = _ipr.get_routes(family=socket.AF_INET)
    for route in route_list:
        edst = "%s/%d" % (route.get_attr("RTA_DST"), route["dst_len"])
        #logging.debug("edst: %s, dst: %s", edst, dst)
        if dst == edst:
            return True
    return False


def _add_route(dst, gw):
    """Add route entry to the OS route table."""

    if dst == "default" or dst == "0.0.0.0":
        if gw == "default":
            logging.error("Can't add default destination to default gateway.")
            raise Error("Can't add default destination to default gateway.")

    if gw == "default":
        gw = _get_default_gw()[0]
        if gw is None:
            logging.error("Address of default gateway is unknown.")
            raise Error("Address of default gateway is unknown.")

    gw_is_dev = len(_ipr.link_lookup(ifname=gw)) > 0

    if not gw_is_dev:
        if not is_address_reachable(gw):
            logging.warning("Gateway address is not reachable. Not adding.")
            return

    if _is_route_exists(dst):
        logging.warning("Route for dst=%s already exists. " +
                        "Deleting existing route.", dst)
        _ipr.route("del", dst=dst)

    if dst == "default" or dst == "0.0.0.0":
        # Deleting all existing default routes
        _del_all_default_routes()

    # Adding new route
    logging.debug("Adding route: %s -> %s.", dst, gw)
    if gw_is_dev:
        os.system("ip route add %s dev %s" % (dst, gw))
    else:
        _ipr.route("add", dst=dst, gateway=gw)


def _del_all_default_routes():
    """Delete all default route entries from OS route table."""

    gw_list = _get_default_gws()
    for ip, ifname, met in gw_list:
        if ip is None:
            if met is None:
                logging.debug("Deleting default route via %s interface.", ifname)
                os.system("ip route del default dev %s" % ifname)
            else:
                logging.debug("Deleting default route via %s interface with metric %d.", ifname, met)
                os.system("ip route del default dev %s metric %d" % (ifname, met))
        else:
            if met is None:
                logging.debug("Deleting default route to %s via %s interface.", ip, ifname)
                os.system("ip route del default via %s dev %s" % (ip, ifname))
            else:
                logging.debug("Deleting default route to %s via %s interface with metric %d.", ip, ifname, met)
                os.system("ip route del default via %s dev %s metric %d" % (ip, ifname, met))


def _del_route(dst, gw=None):
    """Delete route entry from OS route table."""

    if gw is not None:
        logging.debug("Deleting route: %s -> %s.", dst, gw)
        if len(_ipr.link_lookup(ifname=gw)) > 0:
            os.system("ip route del %s dev %s" % (dst, gw))
        else:
            _ipr.route("del", dst=dst, gateway=gw)
    else:
        logging.debug("Deleting route: %s", dst)
        os.system("ip route del %s" % dst)


def _create_tunnel(name, ip, gre_local, gre_remote, route_dst=None):
    """Create GRE tunnel interface with given name and IP address."""

    logging.debug("Creating %s interface.", name)
    _ipr.link("add", ifname=name, kind="gre",
              gre_local=gre_local,
              gre_remote=gre_remote,
              gre_ttl=255)

    logging.debug("Assigning %s address to %s interface.", ip, name)
    index = _ipr.link_lookup(ifname=name)[0]
    _ipr.link("set", index=index, state="down")
    _ipr.addr("add", index=index, address=ip)
    _ipr.link("set", index=index, state="up")

    if route_dst is not None:
        # Adding new route
        _add_route(route_dst, name)


def _create_interface(name, ip, route_dst=None):
    """Create dummy interface with given name and IP address."""

    logging.debug("Creating %s interface.", name)
    _ipr.link("add", ifname=name, kind="dummy")

    logging.debug("Assigning %s address to %s interface.", ip, name)
    index = _ipr.link_lookup(ifname=name)[0]
    _ipr.link("set", index=index, state="down")
    _ipr.addr("add", index=index, address=ip)
    _ipr.link("set", index=index, state="up")

    if route_dst is not None:
        # Adding new route
        _add_route(route_dst, name)


def _destroy_interface(name):
    """Destroy interface with given name."""

    links = _ipr.link_lookup(ifname=name)
    if len(links) == 0:
        logging.warning("Can't destroy %s interface. It doesn't exist.", name)
        return
    index = links[0]

    # IP addresses assigned to interface
    ip_list = _ipr.get_addr(family=socket.AF_INET, label=name)
    for ipo in ip_list:
        ip = ipo.get_attr("IFA_ADDRESS")

        # Deleting routes
        route_list = _ipr.get_routes(family=socket.AF_INET, gateway=ip)
        for route in route_list:
            rip = route.get_attr("RTA_DST") # route["dst_len"] <- mask
            if rip is not None:
                _del_route("%s/%d" % (rip, route["dst_len"]), ip)
        route_list = _ipr.get_routes(family=socket.AF_INET, scope=253)
        for route in route_list:
            if route.get_attr("RTA_OIF") == index:
                rip = route.get_attr("RTA_DST") # route["dst_len"] <- mask
                if rip is not None:
                    _del_route("%s/%d" % (rip, route["dst_len"]), name)

    # Deleting interface
    logging.debug("Destroying %s interface.", name)
    _ipr.link("set", index=index, state="down")
    _ipr.link("del", index=index)


def _destroy_interfaces(name_prefix):
    """Destroy all interfaces with name starting with given name prefix."""

    for link in _ipr.get_links():
        name = link.get_attr('IFLA_IFNAME')
        if name[0:3] == name_prefix:
            _destroy_interface(name)


def get_ip_forward():
    """Return True if IP-Forward is enabled in the OS."""
    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        value = True if int(f.read(1)) == 1 else False
    logging.debug("IP forward is %s.", "enabled" if value else "disabled")
    return value


def set_ip_forward(value):
    """Enable or disable IP-Forward in the OS."""
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n" if value else "0\n")
        logging.debug("IP forward has been %s.", "enabled" if value else "disabled")
    except PermissionError:
        logging.error("Permission denied when trying to %s IP forwarding.", 
                     "enable" if value else "disable")
        logging.error("This operation requires root privileges.")
        raise
    except Exception as e:
        logging.error("Failed to %s IP forwarding: %s", 
                     "enable" if value else "disable", str(e))
        raise


def get_proxy_arp(ifname):
    """Return True if Proxy-ARP is enabled in the OS for
    the given interface name."""

    with open("/proc/sys/net/ipv4/conf/%s/proxy_arp" % ifname, "r") as f:
        value = True if int(f.read(1)) == 1 else False
    logging.debug("Proxy ARP for %s interface is %s.", ifname,
                 "enabled" if value else "disabled")
    return value


def set_proxy_arp(ifname, value):
    """Enable or disable Proxy-ARP for given interface name in the OS."""

    with open("/proc/sys/net/ipv4/conf/%s/proxy_arp" % ifname, "w") as f:
        f.write("1\n" if value else "0\n")
    logging.debug("Proxy ARP for %s interface has been %s.", ifname,
                 "enabled" if value else "disabled")


def set_proxy_arp_for_all(value):
    """Enable or disable Proxy-ARP for all interfaces in the OS."""

    link_list = _ipr.get_links()
    for link in link_list:
        if link.get_attr("IFLA_OPERSTATE") == "UP":
            set_proxy_arp(link.get_attr("IFLA_IFNAME"), value)


def ip_to_int(value):
    """Return integer representation of IP address given in dot notation."""

    return struct.unpack("!I", socket.inet_aton(value))[0]


def int_to_ip(value):
    """Convert given IP address in integer representation to dot notation."""

    return socket.inet_ntoa(struct.pack("!I", value))


def str_to_hex(string):
    """Convert given string to hex string."""
    if isinstance(string, bytes):
        return ":".join("{:02x}".format(c) for c in string)
    else:
        return ":".join("{:02x}".format(ord(c)) for c in string)


class Error(Exception):
    """Unspecified exception raised by MIP module."""
    pass


class RegistrationFailed(Error):
    """Mobile Node Agent registration failed exception."""
    pass


class Extension:
    """Mobile IP Extension class."""

    TYPE_MHAE = 32 # Mobile-Home Authentication Extension
    TYPE_MFAE = 33 # Mobile-Foreign Authentication Extension
    TYPE_FHAE = 34 # Foreign-Home Authentication Extension

    _TYPE_DESC_TABLE = {
        32: "Mobile-Home Authentication Extension",
        33: "Mobile-Foreign Authentication Extension",
        34: "Foreign-Home Authentication Extension"
    }

    def __init__(self, type, length, data=None):
        """MIP Extension constructor.

        Parameters:
        type    -- type of extension (e.g. Extension.TYPE_MHAE)
        length  -- lenght of data (number of bytes) in the extension
        data    -- data in the extension (optional)
        """

        if data is not None and len(data) != length:
            logging.error("Length of data is invalid.")
            raise Error("Length of data is invalid.")
        self.type = type
        self.length = length
        self.data = data

    def __str__(self):
        return "<MobileIP Extension, Type: %d, Length: %d>" % (self.type,
                    self.length)


class MobileHomeAuthExtension(Extension):
    """Mobile IP Mobile-Home Authentication Extension class for 128-bit
    HMAC-MD5."""

    _LENGTH = 20

    def __init__(self, spi, authenticator=None):
        """MHAE constructor.

        Parameters:
        spi           -- SPI value
        authenticator -- Authentication data (optional)
        """

        Extension.__init__(self, Extension.TYPE_MHAE,
                        MobileHomeAuthExtension._LENGTH)
        self.spi = spi
        self.authenticator = authenticator

    def __str__(self):
        return "<MobileIP Mobile-Home Auth Extension, SPI: %d>" % self.spi


class Packet:
    """Mobile IP packet class."""

    TYPE_REG_REQUEST = 1
    TYPE_REG_REPLY = 3

    _TYPE_DESC_TABLE = {
        1: "Registration Request",
        3: "Registration Reply"
    }

    _FORMAT = "!B" # MIP packet format: first byte defines packet Type

    def __init__(self, type, extensions=None):
        """MIP packet constructor.

        Parameters:
        type       -- type of MIP packet (e.g. Packet.TYPE_REG_REQUEST)
        extensions -- list of Extension instances (optional)
        """

        self.type = type
        self.extensions = [] if extensions is None else extensions

    def __str__(self):
        return "<MobileIP packet, Type: %i (%s), Extensions: %s>" % (
            self.type, Packet._TYPE_DESC_TABLE[self.type], self.extensions)

    def to_data(self):
        """Return byte array representation of the packet."""

        logging.error("Unable to get data.")
        raise Error("Unable to get data.")

    def _calculate_mhae(self, spi, key):
        """Create and return MobileHomeAuthExtension of this packet."""

        packed = self.to_data()
        extension = MobileHomeAuthExtension(spi)
        try:
            packed += struct.pack("!2BI", extension.type, extension.length, spi)
        except struct.error:
            logging.error("Invalid MIP Mobile-Home Auth Extension fields.")
            raise Error("Invalid MIP Mobile-Home Auth Extension fields.")
        
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        extension.authenticator = hmac.new(key, packed, digestmod='md5').digest()
        return extension

    def add_mhae(self, spi, key):
        """Create and add MobileHomeAuthExtension of this packet
        with given SPI and KEY."""

        # Deleting existing MHAE
        for extension in self.extensions[:]:
            if extension.type == Extension.TYPE_MHAE:
                self.extensions.remove(extension)
        self.extensions.append(self._calculate_mhae(spi, key))

    def get_mhae(self):
        """Return MobileHomeAuthExtension of this packet."""

        for extension in self.extensions:
            if extension.type == Extension.TYPE_MHAE:
                return extension

    def verify_mhae(self, spi, key):
        """Return True if MobileHomeAuthExtension in this packet is valid
        for given SPI and KEY."""

        new_extensions = []
        for extension in self.extensions:
            if extension.type == Extension.TYPE_MHAE and extension.spi == spi:
                mhae = extension
                break
            new_extensions.append(extension)
        old_extensions = self.extensions
        self.extensions = new_extensions
        authenticator = self._calculate_mhae(spi, key).authenticator
        self.extensions = old_extensions
        return mhae.authenticator == authenticator

    @staticmethod
    def from_data(data):
        """Create and return MIP packet based on given byte data."""

        try:
            unpacked = struct.unpack(Packet._FORMAT,
                data[0:struct.calcsize(Packet._FORMAT)])
        except struct.error:
            logging.error("Invalid MIP packet.")
            raise Error("Invalid MIP packet.")

        if unpacked[0] == Packet.TYPE_REG_REQUEST:
            return RegRequestPacket.from_data(data)
        if unpacked[0] == Packet.TYPE_REG_REPLY:
            return RegReplyPacket.from_data(data)

        logging.error("Unknown MIP packet type.")
        raise Error("Unknown MIP packet type.")

    @staticmethod
    def _extensions_from_data(data):
        """Create and return list Extension instances based on
        given byte data."""

        extensions = []
        i = 0
        while i < len(data):
            try:
                unpacked = struct.unpack("!2B", data[i:i+2])
            except struct.error:
                logging.error("Invalid MIP Extension data.")
                raise Error("Invalid MIP Extension data.")

            type = unpacked[0]
            length = unpacked[1]

            if type == Extension.TYPE_MHAE:
                try:
                    unpacked = struct.unpack("!I", data[i+2:i+2+4])
                except struct.error:
                    logging.error("Invalid MIP Mobile-Home Auth Extension data.")
                    raise Error("Invalid MIP Mobile-Home Auth Extension data.")
                spi = unpacked[0]
                authenticator = data[i+2+4:i+2+length]
                extensions.append(MobileHomeAuthExtension(spi,
                    authenticator=authenticator))
            else:
                extensions.append(Extension(type, length,
                    data[i+2:i+2+length]))

            i += 2+length

        return extensions

    def _extensions_to_data(self, packed):
        for extension in self.extensions:
            if isinstance(extension, MobileHomeAuthExtension):
                try:
                    packed += struct.pack("!2BI",extension.type,
                        extension.length, extension.spi)
                    packed += extension.authenticator[0:extension.length-4]
                except struct.error:
                    logging.error("Invalid MIP Mobile-Home Auth Extension fields.")
                    raise Error("Invalid MIP Mobile-Home Auth Extension fields.")
            else:
                try:
                    packed += struct.pack("!2B", extension.type,
                        extension.length) + extension.data[0:extension.length]
                except struct.error:
                    logging.error("Invalid MIP Extension fields.")
                    raise Error("Invalid MIP Extension fields.")
        return packed


class RegRequestPacket(Packet):
    """Mobile IP Registration Request packet class."""

    FLAG_S = 0B10000000  # Simultaneous bindings
    FLAG_B = 0B01000000  # Broadcast datagrams
    FLAG_D = 0B00100000  # Decapsulation by mobile node
    FLAG_M = 0B00010000  # Minimal encapsulation
    FLAG_G = 0B00001000  # GRE encapsulation
    FLAG_r = 0B00000100  # reserved
    FLAG_T = 0B00000010  # Reverse Tunneling requested
    FLAG_x = 0B00000001  # reserved

    _FLAG_DESC_TABLE = {
        0B10000000: "S",
        0B01000000: "B",
        0B00100000: "D",
        0B00010000: "M",
        0B00001000: "G",
        0B00000100: "r",
        0B00000010: "T",
        0B00000001: "x"
    }

    _FORMAT = "!2B H 5I"

    def _print_flags_desc(self):
        desc = ""
        for key, value in RegRequestPacket._FLAG_DESC_TABLE.items():
            desc += value if self.flags & key else ""
        return desc

    def __init__(
            self,
            flags,
            lifetime,
            home_address,
            home_agent,
            care_of_address,
            identification = None, # timestamp
            extensions = None
        ):
        """MIP Registration Request constructor.

        Parameters:
        flags           -- flags that will be included in to request
        lifetime        -- Lifetime value
        home_address    -- Home IP address (dot notation)
        home_agent      -- Home Agent IP address (dot notation)
        care_of_address -- Care-of IP address (dot notation)
        identification  -- Identification value
        extensions      -- list of Extension instances
        """
        Packet.__init__(self, Packet.TYPE_REG_REQUEST, extensions)
        self.flags = flags
        self.lifetime = lifetime
        self.home_address = home_address
        self.home_agent = home_agent
        self.care_of_address = care_of_address
        self.identification = (system_to_ntp_time(time.time())
                               if identification is None else identification)
        self.expiration_date = 0 # timestamp when binding will expire

    def __str__(self):
        return ("<MobileIP Reg Request, Flags: %d (%s), Lifetime: %d, " +
        "Home address: %s, Home agent: %s, Care-of address: %s, " +
        "Identification: %f, Extensions: %s>") % (
            self.flags,
            self._print_flags_desc(),
            self.lifetime,
            self.home_address,
            self.home_agent,
            self.care_of_address,
            self.identification,
            self.extensions
        )

    def is_update_request(self, reg_req_packet):
        """Return True if given RegRequestPacket is an update."""

        return (self.home_address == reg_req_packet.home_address and
                self.home_agent == reg_req_packet.home_agent and
                self.care_of_address == reg_req_packet.care_of_address)

    def update_identification(self):
        """Update Identification value in the request."""

        self.identification = system_to_ntp_time(time.time())

    @staticmethod
    def from_data(data):
        """Create and return RegRequestPacket based on given byte data."""

        try:
            unpacked = struct.unpack(
                RegRequestPacket._FORMAT,
                data[0:struct.calcsize(RegRequestPacket._FORMAT)])
        except struct.error:
            logging.error("Invalid MIP Registration Request packet.")
            raise Error("Invalid MIP Registration Request packet.")

        extensions = Packet._extensions_from_data(
            data[struct.calcsize(RegRequestPacket._FORMAT):len(data)])

        return RegRequestPacket(
                unpacked[1],
                unpacked[2],
                int_to_ip(unpacked[3]),
                int_to_ip(unpacked[4]),
                int_to_ip(unpacked[5]),
                timestamp_to_time(unpacked[6], unpacked[7]),
                extensions
        )

    def to_data(self):
        """Return byte array representation."""

        try:
            packed = struct.pack(RegRequestPacket._FORMAT,
                self.type,
                self.flags,
                self.lifetime,
                ip_to_int(self.home_address),
                ip_to_int(self.home_agent),
                ip_to_int(self.care_of_address),
                timestamp_to_int(self.identification),
                timestamp_to_frac(self.identification)
            )
        except struct.error:
            logging.error("Invalid Registration Request packet fields.")
            raise Error("Invalid Registration Request packet fields.")
        return self._extensions_to_data(packed)


class RegReplyPacket(Packet):
    """Mobile IP Registration Reply packet class."""

    CODE_ACCEPTED = 0
    CODE_DENIED_BY_FA = 64
    CODE_DENIED_BY_HA = 128
    CODE_MN_FAILED_AUTH = 131
    CODE_IDENT_MISMATCH = 133

    _CODE_DESC_TABLE = {
        0: "Registration accepted",
        1: "Registration accepted, mobility bindings unsupported",
        64: "Reason unspecified",
        65: "Administratively prohibited",
        66: "Insufficient resources",
        67: "Mobile node failed authentication",
        68: "Home agent failed authentication",
        69: "Requested Lifetime too long",
        70: "Poorly formed Request",
        71: "Poorly formed Reply",
        72: "Requested encapsulation unavailable",
        73: "Reserved and unavailable",
        77: "Invalid care-of address",
        78: "Registration timeout",
        80: "Home network unreachable (ICMP error received)",
        81: "Home agent host unreachable (ICMP error received)",
        82: "Home agent port unreachable (ICMP error received)",
        88: "Home agent unreachable (other ICMP error received)",
        194: "Invalid Home Agent Address",
        128: "Reason unspecified",
        129: "Administratively prohibited",
        130: "Insufficient resources",
        131: "Mobile node failed authentication",
        132: "Foreign agent failed authentication",
        133: "Registration Identification mismatch",
        134: "Poorly formed Request",
        135: "Too many simultaneous mobility bindings",
        136: "Unknown home agent address"
    }

    _FORMAT = "!2B H 4I"

    def __init__(
            self,
            code,
            lifetime,
            home_address,
            home_agent,
            identification,
            extensions = None,
        ):
        """MIP Registration Reply constructor.

        Parameters:
        code            -- code of the reply (e.g. RegReplyPacket.CODE_ACCEPTED)
        lifetime        -- Lifetime value
        home_address    -- Home IP address (dot notation)
        home_agent      -- Home Agent IP address (dot notation)
        identification  -- Identification value
        extensions      -- list of Extension instances
        """

        Packet.__init__(self, Packet.TYPE_REG_REPLY, extensions)
        self.code = code
        self.lifetime = lifetime
        self.home_address = home_address
        self.home_agent = home_agent
        self.identification = identification
        self.expiration_date = 0 # timestamp when binding will expire

    def __str__(self):
        return ("<MobileIP Reg Reply, Code: %d (%s), Lifetime: %d, " +
        "Home address: %s, Home agent: %s, Identification: %f, " +
        "Extensions: %s>") % (
            self.code,
            RegReplyPacket._CODE_DESC_TABLE[self.code],
            self.lifetime,
            self.home_address,
            self.home_agent,
            self.identification,
            self.extensions
        )

    @staticmethod
    def from_data(data):
        """Create and return RegReplyPacket based on given byte data."""

        try:
            unpacked = struct.unpack(
                RegReplyPacket._FORMAT,
                data[0:struct.calcsize(RegReplyPacket._FORMAT)])
        except struct.error:
            logging.error("Invalid MIP Registration Reply packet.")
            raise Error("Invalid MIP Registration Reply packet.")

        extensions = Packet._extensions_from_data(
            data[struct.calcsize(RegReplyPacket._FORMAT):len(data)])

        return RegReplyPacket(
                unpacked[1],
                unpacked[2],
                int_to_ip(unpacked[3]),
                int_to_ip(unpacked[4]),
                timestamp_to_time(unpacked[5], unpacked[6]),
                extensions
        )

    def to_data(self):
        """Return byte array representation."""

        try:
            packed = struct.pack(RegReplyPacket._FORMAT,
                self.type,
                self.code,
                self.lifetime,
                ip_to_int(self.home_address),
                ip_to_int(self.home_agent),
                timestamp_to_int(self.identification),
                timestamp_to_frac(self.identification)
            )
        except struct.error:
            logging.error("Invalid MIP Registration Reply packet fields.")
            raise Error("Invalid MIP Registration Reply packet fields.")
        return self._extensions_to_data(packed)
