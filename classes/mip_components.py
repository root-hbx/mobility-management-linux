"""Mobile IP component classes.

This module contains the main Mobile IP protocol component implementations:
- HomeAgent: Handles registration requests from mobile nodes
- MobileNodeAgent: Manages mobility for mobile nodes
"""

import threading
import time
import socket
import logging
import os
from netaddr import IPNetwork
from .mip_commands import BindingChecker, Timer
from ntplib import ntp_to_system_time

# All helper funcs and classes are defined in mip.py
from .mip_helper import (
    INFINITE_LIFETIME,
    
    get_ifname, get_address, get_interfaces_states,
    _get_default_gw, _get_default_gws,
    is_address_in_subnet, is_address_reachable,
    _is_route_exists, _add_route, _del_all_default_routes, _del_route,
    _create_tunnel, _create_interface, _destroy_interface, _destroy_interfaces,
    get_ip_forward, set_ip_forward,
    get_proxy_arp, set_proxy_arp, set_proxy_arp_for_all,
    ip_to_int, int_to_ip, str_to_hex, 

    Error, RegistrationFailed, 
    Extension, MobileHomeAuthExtension,
    Packet, RegRequestPacket, RegReplyPacket
)


class MobileNodeAgent:
    """Mobile IP Mobile Node agent"""

    def __init__(self, mhae_spi, mhae_key, home_agent, home_address,
                 interfaces,
                 port=434,
                 flags=(RegRequestPacket.FLAG_D |
                        RegRequestPacket.FLAG_G |
                        RegRequestPacket.FLAG_T),
                 timeout=3,
                 num_of_retr=2,
                 rereg_time=0.8,
                 wait_for_dereg_reply=True,
        ):
        """Mobile Node Agent constructor.

        Parameters:
        mhae_spi             -- SPI value needed for MHAE calculation (decimal integer)
        mhae_key             -- KEY value needed for MHAE calculation (string)
        home_agent           -- Home Agent IP address (dot notation)
        home_address         -- Home IP address (dot notation)
        interfaces           -- dict that conctains interface names as keys
                                and default gateway IP addresses as values,
                                e.g. {"eth0": "10.1.2.5", "wlan0": "10.1.3.5"}
        port                 -- Home Agent service UDP port number (default is 434)
        flags                -- flags included in MIP requests
                                (default is FLAG_D | FLAG_G | FLAG_T)
        timeout              -- maximum waiting time (seconds) for
                                the HA response (default is 3)
        num_of_retr          -- number of request retries (default is 2)
        rereg_time           -- requested time of reregistration,
                                e.g. 0.5 means that reregistraton will be
                                after 0.5*lifetime (default is 0.8)
        wait_for_dereg_reply -- indicator if agent should wait for
                                deregistration reply form HA (default is True)
        """

        # Only co-located care-of address is supported, so
        # D flag (Decapsulation by mobile node) is mandatory.
        # Only GRE tunnel is supported, so G flag is mandatory and M is not allowed.
        # Reverse Tunneling is mandatory, so T flag is mandatory
        if not flags & RegRequestPacket.FLAG_D:
            raise Error("D flag is not set but is mandatory.")
        if not flags & RegRequestPacket.FLAG_G:
            raise Error("G flag is not set but is mandatory.")
        if not flags & RegRequestPacket.FLAG_T:
            raise Error("T flag is not set but is mandatory.")
        if flags & RegRequestPacket.FLAG_M:
            raise Error("M flag is set but is not supported.")

        self.mhae_spi = mhae_spi
        self.mhae_key = mhae_key
        self.home_agent = home_agent
        self.home_address = home_address
        self.port = port
        self.flags = flags
        self.timeout = timeout
        self.num_of_retr = num_of_retr
        self.rereg_time = rereg_time
        self.wait_for_dereg_reply =  wait_for_dereg_reply
        self._listening = False
        self._rereg_timer = None
        self._socket = None
        self._sent_reg_reqest = None
        self._received_reg_reply = None
        self._num_of_retr_done = 0
        self._closing = False
        self._is_rereg = False
        self._exception_handler = None
        self._gateway = None
        self._interfaces = interfaces
        self._lock = threading.Lock()

        # Create dummy interface with home address
        _destroy_interfaces("mip")
        _del_route(home_agent+"/32")
        _create_interface("mip0", home_address)


    def __del__(self):
        """Mobile Node Agent destructor"""

        try:
            _destroy_interfaces("mip") # Destroying all mipX interfaces
            set_ip_forward(False) # Disabling kernel IP forwarding
            set_proxy_arp_for_all(False) # Disabling Proxy ARP
        except:
            pass


    def _update_routes(self, ifname):
        """Create or update static route to Home Agent IP address."""

        # Checking if Home Agent is on loopback
        if self.home_agent.startswith("127."):
            logging.info("Home Agent is on loopback, skipping route updates.")
            return
        
        # Getting default gateway
        gw = self._interfaces[ifname]
        if gw is None:
            logging.error("Unknown gateway address.")
            raise Error("Unknown gateway address.")
        # Creating static route to home agent
        _add_route(self.home_agent+"/32", gw)


    def _create_tunnel(self, reg_req_packet):
        """Create GRE tunnel to Home Agent IP address."""

        #ifname, prefixlen = get_ifname(reg_req_packet.care_of_address)
        #gw = self._interfaces[ifname]
        #if gw is None:
            #gw = _get_default_gw()[0]
            #if gw is None:
        #    raise Error("Unknown gateway address.")
            #self._gateway = gw # Saving default route gateway

        # Creating static route to home agent
        #_add_route(self.home_agent+"/32", gw)

        _create_tunnel(name="mip1",
                       ip=self.home_address,
                       gre_local=reg_req_packet.care_of_address,
                       gre_remote=reg_req_packet.home_agent,
                       route_dst="default")


    def _destroy_tunnel(self):
        """Destroy GRE tunnel to Home Agent IP address."""

        _destroy_interface("mip1")

        #if self._gateway is not None:
        #    # Recreating original default routing
        #    _add_route(dst="default", gw=self._gateway)
        #    self._gateway = None

        # Recreating default routing
        #for ifname in self._interfaces.keys():
        #    if is_address_reachable(self._interfaces[ifname]):
        #        logging.info("Setting default route for %s interface.", ifname)
        #        _add_route(dst="default", gw=self._interfaces[ifname])
        #        break

        # Deleting static route to home agent
        #_del_route(self.home_agent+"/32")


    def _stop_listening_stuff(self):
        # Destroying tunnel
        if self.is_registered():
            self._destroy_tunnel()
            #_del_route(self.home_agent+"/32")

        self._sent_reg_reqest = None
        self._is_rereg = False
        self._stop_listening()


    def _data_handler(self, data, addr):
        """Handle received data."""

        try:
            in_packet = Packet.from_data(data)
        except Error:
            logging.error("Invalid data received.")
            return

        logging.debug("Connected by %s host on %d port.", addr[0], addr[1])
        logging.debug("Received: %s", in_packet)
        #logging.debug("Extensions:")
        #for extension in in_packet.extensions:
        #    logging.info(extension)

        if not isinstance(in_packet, RegReplyPacket):
            logging.error("Invalid packet type has been received. " +
                            "Discarding packet.")
            return

        # Registration Reply received
        logging.info("Registration Reply has been received.")

        # Identification verification
        if in_packet.identification != self._sent_reg_reqest.identification:
            logging.warning("Reply has unknown identification. " +
                            "Discarding packet.")
            return

        # MHAE verification
        mhae = in_packet.get_mhae()
        if mhae is None or mhae.spi != self.mhae_spi:
            # Can't find matching SPI
            logging.warning("Can't find matching MHAE SPI in reply. " +
                            "Discarding packet.")
            return
        if not in_packet.verify_mhae(self.mhae_spi, self.mhae_key):
            # Authorization failed
            logging.warning("Reply authorization is failed.")
            self._stop_listening_stuff()
            self._lock.release()
            raise RegistrationFailed("Reply authorization is failed.")

        # Registration Reply code verification
        if in_packet.code is not RegReplyPacket.CODE_ACCEPTED:
            # Registration is not accepted
            logging.warning("Registration request has not been accepted.")
            self._stop_listening_stuff()
            self._lock.release()
            raise RegistrationFailed("Registration has not been accepted.")

        # Registration Reply lifetime verification
        if in_packet.lifetime <= 0:
            # Registration lifetime is 0
            if self._sent_reg_reqest.lifetime != 0:
                logging.warning("Reply lifetime is 0, but 0 wasn't requested.")
            logging.debug("Reply lifetime is 0, so reply for deregistration.")
            self._stop_listening_stuff()
            return

        # Registration is accepted
        logging.info("Registration request has been accepted.")

        # Verifing reply lifetime
        if in_packet.lifetime > self._sent_reg_reqest.lifetime:
            logging.warning("Lifetime in reply is longer than requested.")
            in_packet.lifetime = self._sent_reg_reqest

        # Saving reply
        self._received_reg_reply = in_packet

        # Setting up reregistration timer
        if self._rereg_timer is not None:
            logging.error("Rereg timer is not empty.")
        self._rereg_timer = Timer(
            in_packet.lifetime * self.rereg_time, self._reregister,
            exception_handler=self._exception_handler)
        self._rereg_timer.start()

        # Creating tunnel
        if not self._is_rereg:
            #if self._sent_reg_reqest.flags & RegRequestPacket.FLAG_T:
            self._create_tunnel(self._sent_reg_reqest)

        self._stop_listening()
        self._is_rereg = False


    def _send_packet(self, packet, addr):
        """Send given packet to given IP address."""

        logging.debug("Sending: %s", packet)
        self._socket.sendto(packet.to_data(), addr)


    def is_registered(self):
        """Return True if agent is registered."""

        if self._is_rereg:
            return True
        return self._received_reg_reply is not None


    def get_status(self):
        """Return string containing status information."""

        if not self.is_registered():
            return {"registered": False}
        ifname, prefixlen = get_ifname(address=self._sent_reg_reqest.care_of_address)
        if ifname is None:
            logging.error("Care-of address %s is not assigned " +
                          "to any interface.", self._sent_reg_reqest.care_of_address)
        return {
            "registered": True,
            "home_address": self.home_address,
            "home_agent": self.home_agent,
            "care_of_address": self._sent_reg_reqest.care_of_address,
            "ifname": ifname
            }


    def register(self, 
                 care_of_address=None, 
                 dereg_existing_reg=True,
                 lifetime=INFINITE_LIFETIME, 
                 ifname=None,
                 exception_handler=None
    ):
        """Register Mobile Node Agent in Home Agent.

        Parameters:
        care_of_address    -- Care-of address (optional if ifname is provided)
        dereg_existing_reg -- if True, deregistration will be done
                              before new registration (default is True)
        lifetime           -- requested registration lifetime value
        ifname             -- name of network interface for the registration
                              (optional if care_of_address is provided)
        exception_handler  -- function that will be called when exception
                              occures in Mobile Node Agent thread
        """

        self._lock.acquire()

        prefixlen = None

        # Addresses verification
        if care_of_address is None and ifname is None:
            logging.error("At least care-of address or interface " +
                          "name needs to be provided.")
            self._lock.release()
            raise Error("Care-of address or interface name not provided")
        if care_of_address is None:
            care_of_address, prefixlen = get_address(ifname=ifname)
            if care_of_address is None or prefixlen is None:
                logging.error("Interface %s has no address assigned or " +
                              "doesn't exist.", ifname)
                self._lock.release()
                raise RegistrationFailed("Interface has no address assigned.")
        if ifname is None or prefixlen is None:
            ifname, prefixlen = get_ifname(address=care_of_address)
            if ifname is None or prefixlen is None:
                logging.error("Care-of address %s is not assigned " +
                              "to any interface.", care_of_address)
                self._lock.release()
                raise RegistrationFailed("Care-of address is not assigned to any interface.")
        if is_address_in_subnet(self.home_address,
                                "%s/%d"%(care_of_address, prefixlen)):
            logging.error("Home address (%s) belongs to " +
                          "care-of address subnet (%s/%d), so you are in " +
                          "the home network.", self.home_address,
                          care_of_address, prefixlen)
            self._lock.release()
            raise RegistrationFailed("Home address belongs to care-of address subnet.")

        # Check if already registered
        if self.is_registered():
            if (self._sent_reg_reqest.care_of_address == care_of_address and
                self.rereg_time is not None):
                self._exception_handler = exception_handler # updating handler
                logging.warning("Care-of address is already registered. "+
                                "Request will not be sent.")
                self._lock.release()
                return

        # Disabling rereg timer
        if self._rereg_timer is not None:
            self._rereg_timer.cancel()
            self._rereg_timer = None

        # Updating routes for home gateway
        self._update_routes(ifname)

        # Auto deregistration
        if self.is_registered():
            if dereg_existing_reg:
                self.deregister(ifname=ifname)
            else:
                self.cancel()

        # Resets
        #self._destroy_tunnel()
        self._closing = False
        self._received_reg_reply = None
        self._num_of_retr_done = 0
        self._is_rereg = False

        # Creating Registration Request
        out_packet = RegRequestPacket(
            flags=self.flags,
            lifetime=lifetime,
            home_address=self.home_address,
            home_agent=self.home_agent,
            care_of_address=care_of_address
        )
        out_packet.add_mhae(self.mhae_spi, self.mhae_key)

        # Saving reg request
        self._sent_reg_reqest = out_packet
        self._exception_handler = exception_handler

        logging.info("Sending Registration Request to %s (Home Agent) " +
                     "using %s interface.", self.home_agent, ifname)
        #logging.debug("care_of_address: %s, ifname: %s, prefixlen: %s",
        #              care_of_address, ifname, prefixlen)
        #TODO(bxhu): test for local loopback address
        # Prev:
        # self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self._socket.bind((care_of_address, 0))
        # self._socket.setsockopt(socket.SOL_SOCKET,
        #                         socket.SO_BINDTODEVICE, ifname.encode())
        # Current:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.home_agent.startswith("127."):
            logging.info("Home Agent is on loopback. Binding to loopback interface.")
            # When accessing the local loopback address, 
            # you do not need to bind to a specific interface,
            # just use the loopback interface directly.
            self._socket.bind(('127.0.0.1', 0))
            logging.debug("Socket bound to: %s", str(self._socket.getsockname()))
        else:
            # Normally, bind to the external interface
            self._socket.bind((care_of_address, 0))
            self._socket.setsockopt(socket.SOL_SOCKET,
                                socket.SO_BINDTODEVICE, ifname.encode())
        
        self._send_packet(out_packet, (self.home_agent, self.port))

        logging.info("Waiting for registration reply...")
        
        # Listening for reply
        self._start_listening()
        self._lock.release()


    def deregister(self, ifname=None, wait_for_reply=None):
        """Deregister Mobile Node Agent.

        Parameters:
        ifname         -- name of network interface for the deregistration,
                          if not provided ifname will the same as for
                          the registration (optional)
        wait_for_reply -- if True, positive reply from Home Agent is required
                          to accept deregistration (default is
                          wait_for_dereg_reply provided in constructor)
        """

        # Disabling rereg timer
        if self._rereg_timer is not None:
            self._rereg_timer.cancel()
            self._rereg_timer = None

        if not self.is_registered():
            logging.warning("There is nothing to deregister.")
            return

        # Resets
        self._received_reg_reply = None
        self._num_of_retr_done = self.num_of_retr # disable retransmissions
        self._rereg_timer = None
        self._closing = False

        self._is_rereg = True

        # Creating Deregistration Request
        self._sent_reg_reqest.update_identification()
        self._sent_reg_reqest.lifetime = 0 # Deregistration
        self._sent_reg_reqest.add_mhae(self.mhae_spi, self.mhae_key)

        care_of_address = self._sent_reg_reqest.care_of_address
        difname, prefixlen = get_ifname(address=care_of_address)

        if ifname is None and difname is None:
            logging.error("Care-of address %s is not assigned " +
                          "to any interface. Cancelling registration.",
                          care_of_address)
            self.cancel()
            self._lock.release()
            return

        if ifname is None or difname == ifname:
            logging.debug("Care-of address %s is assigned " +
                         "to interface.", care_of_address)
        else:
            address, prefixlen = get_address(ifname=ifname)
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((address, 0))
            self._socket.setsockopt(socket.SOL_SOCKET,
                                    socket.SO_BINDTODEVICE, ifname.encode())

        logging.info("Sending Deregistration Request to %s (Home Agent) " +
                     "via %s interface.",
                     self._sent_reg_reqest.home_agent, ifname)

        self._send_packet(self._sent_reg_reqest,
                          (self._sent_reg_reqest.home_agent, self.port))

        if (self.wait_for_dereg_reply if wait_for_reply is None
            else wait_for_reply):
            # Waiting for reply
            #logging.info("Waiting for deregistration reply.")
            self._start_listening()
        else:
            self._is_rereg = False
            # Not waiting for reply, so destroying reverse tunnel immediately
            #if self._sent_reg_reqest.flags & RegRequestPacket.FLAG_T:
            self._destroy_tunnel()


    def _handle_listening_timeout(self):
        logging.warning("Request has timeout.")
        if self.num_of_retr > self._num_of_retr_done and not self._closing:
            # Doing retransmission
            self._num_of_retr_done += 1 # increasing counter
            logging.warning("Repeating request, #%d attempt.",
                         self._num_of_retr_done)

            self._sent_reg_reqest.add_mhae(self.mhae_spi, self.mhae_key)
            self._send_packet(self._sent_reg_reqest,
                              (self.home_agent, self.port))
        else:
            # Reg request is failed
            logging.error("Registration Request is failed due to timeout.")
            self.cancel()
            return


    def _reregister(self):
        self._lock.acquire()

        logging.info("Refreshing registration.")

        care_of_address = self._sent_reg_reqest.care_of_address
        ifname, prefixlen = get_ifname(address=care_of_address)

        if ifname is None or prefixlen is None:
            logging.error("Care-of address %s is not assigned " +
                          "to any interface. Cancelling registration.",
                          care_of_address)
            self.cancel()
            self._lock.release()
            return

        # Resets
        self._received_reg_reply = None
        self._num_of_retr_done = 0
        self._rereg_timer = None
        self._is_rereg = True

        # Updating Registration Request
        self._sent_reg_reqest.update_identification()
        self._sent_reg_reqest.add_mhae(self.mhae_spi, self.mhae_key)

        logging.info("Sending Registration Request to %s (Home Agent) " +
                     "using %s interface.", self._sent_reg_reqest.home_agent,
                     ifname)
        #logging.debug("care_of_address: %s, ifname: %s, prefixlen: %s",
        #              care_of_address, ifname, prefixlen)
        self._send_packet(self._sent_reg_reqest,
                          (self._sent_reg_reqest.home_agent, self.port))

        self._start_listening()
        self._lock.release()


    def _start_listening(self):
        self._listening = True

        # Staring listening for reply
        while self._listening and not self._closing:
            self._socket.settimeout(self.timeout) # Setting up timeout
            try:
                data, addr = self._socket.recvfrom(1024)
            except socket.timeout:
                self._handle_listening_timeout() # Timeout
            else:
                self._data_handler(data, addr) # Data received
        self._listening = False


    def _stop_listening(self):
        self._listening = False


    def cancel(self):
        """Cancel any ongoing registrations or registration attempts."""

        if self.is_registered():
            logging.info("Cancelling registration.")
            #_del_route(self.home_agent+"/32")
        self._closing = True
        if self._rereg_timer is not None:
            self._rereg_timer.cancel()
            self._rereg_timer = None
        self._destroy_tunnel()
        self._received_reg_reply = None
        self._sent_reg_reqest = None
        self._is_rereg = False
        self._gateway = None


class HomeAgent:
    """Mobile IP Home Agent class."""

    def __init__(self,
                 auth_table,
                 address="0.0.0.0",
                 port=434,
                 max_lifetime=INFINITE_LIFETIME, # Maximum acceptable Lifetime for registration
                 max_ident_mismatch=7, # Accepted timestamp mismatch in sec for identification
                 ip_pool="172.16.0.0/24"):
        """Home Agent constructor.

        Parameters:
        auth_table         -- dict that conctains SPIs as keys and
                              authorization KEYs as values
                              (e.g. {256: "1234567812345678"})
        address            -- Home Agent binding IP address (default is 0.0.0.0,
                              HA will listen on all network interfaces)
        port               -- Home Agent listening UDP port number (default is 434)
        max_lifetime       -- maximum acceptable Lifetime for registration
                              (default is INFINITE_LIFETIME)
        max_ident_mismatch -- accepted timestamp mismatch in seconds for
                              identification (default is 7)
        ip_pool            -- IP pool used for tunnel interfaces
                              (default is 172.16.0.0/24)
        """

        # Check if auth table is valid
        if len(auth_table) == 0:
            raise Error("Auth table is empty.")

        self.auth_table = auth_table
        self.address = address
        self.port = port
        self.max_lifetime = max_lifetime
        self.max_ident_mismatch = max_ident_mismatch
        self._ip_pool = IPNetwork(ip_pool)
        self._socket = None
        self._binding_table = {}
        self._binding_table_lock = threading.Lock()
        self._binding_checker = BindingChecker(
            lock=self._binding_table_lock,
            binding_table=self._binding_table,
            lifetime_expired_handler=self._lifetime_expired_handler)


    def __del__(self):
        """Home Agent destructor"""
        try:
            _destroy_interfaces("haip") # Destroying all mipX interfaces
            set_ip_forward(False) # Disabling kernel IP forwarding
            set_proxy_arp_for_all(False) # Disabling Proxy ARP
        except:
            pass


    def _lifetime_expired_handler(self, reg_req_packet):
        """Handle registration expiration"""

        logging.warning("Binding [home address=%s, CoA=%s] has expired.",
                     reg_req_packet.home_address,
                     reg_req_packet.care_of_address)
        self._destroy_binding(reg_req_packet)


    def _print_binding_table(self):
        """Return registration binding table description."""

        desc = "{"
        for key, value in self._binding_table.items():
            desc += "[home address=%s, CoA=%s]" % (key, value.care_of_address)
        return desc + "}"


    def _get_binding(self, home_address):
        """Return RegRequestPacket used in the registration for
        given Home address."""

        if home_address in self._binding_table:
            return self._binding_table[home_address]
        return None


    def _destroy_binding(self, reg_req_packet):
        """Destroy registration binding for given RegRequestPacket."""

        if reg_req_packet.home_address in self._binding_table:
            self._destroy_tunnel(reg_req_packet)
            self._binding_table_lock.acquire()
            logging.debug("Destroing [home address=%s, CoA=%s] binding.",
                         reg_req_packet.home_address,
                         reg_req_packet.care_of_address)
            del self._binding_table[reg_req_packet.home_address]
            self._binding_table_lock.release()
        else:
            logging.warning("Unable to find binding for home address=%s.",
                            reg_req_packet.home_address)


    def _create_binding(self, reg_req_packet):
        """Create registration binding for given RegRequestPacket."""

        # Computing new expiration date
        expiration_date = (0 if reg_req_packet.lifetime == INFINITE_LIFETIME
                           else time.time() + reg_req_packet.lifetime)

        # Handling existing binding
        existing_reg_req_packet = self._get_binding(reg_req_packet.home_address)
        if existing_reg_req_packet is not None:
            if existing_reg_req_packet.is_update_request(reg_req_packet):
                # reg_req_packet is an update, so updating only expiration_date
                logging.debug("Updating [home address=%s, CoA=%s] binding.",
                             existing_reg_req_packet.home_address,
                             existing_reg_req_packet.care_of_address)
                existing_reg_req_packet.expiration_date = expiration_date
                return
            # reg_req_packet is not an update, so destroying existing binding
            self._destroy_binding(existing_reg_req_packet)

        # Creating new binding
        self._binding_table_lock.acquire()
        logging.debug("Creating new binding [home address=%s, CoA=%s].",
                     reg_req_packet.home_address,
                     reg_req_packet.care_of_address)
        reg_req_packet.expiration_date = expiration_date
        self._binding_table[reg_req_packet.home_address] = reg_req_packet
        self._binding_table_lock.release()

        # Create tunnel
        self._create_tunnel(reg_req_packet)


    def _get_binding_id(self, home_address):
        """Return id of registration binding for given Home Address."""

        return list(self._binding_table.keys()).index(home_address)


    def _create_tunnel(self, reg_req_packet):
        """Create GRE tunnel for given RegRequestPacket."""

        tid = self._get_binding_id(reg_req_packet.home_address)
        tunnel_name = "haip"+str(tid)

        # check if GRE tunneling is supported
        gre_supported = False
        try:
            gre_check = os.popen("lsmod | grep gre").read()
            if gre_check or os.path.exists("/proc/net/gre"):
                gre_supported = True
            else:
                os.system("modprobe ip_gre 2>/dev/null")
                gre_check = os.popen("lsmod | grep gre").read()
                gre_supported = bool(gre_check)
        except Exception:
            pass

        if not gre_supported:
            logging.warning("GRE tunneling appears to be unsupported on this system. " +
                        "Please check your system configuration...")

        # check if tunnel interface already exists
        try:
            # if so, destroy it first
            interfaces = os.popen("ip link show").read()
            if f"{tunnel_name}:" in interfaces:
                logging.info("Tunnel interface %s already exists. Destroying it first.", tunnel_name)
                _destroy_interface(tunnel_name)
        except Exception as e:
            logging.warning("Error checking existing interfaces: %s", str(e))

        try:
            _create_tunnel(name=tunnel_name,
                           ip=str(self._ip_pool[tid+1]),
                           gre_local=self.address,
                           gre_remote=reg_req_packet.care_of_address,
                           route_dst=reg_req_packet.home_address+"/32")
            logging.info("Successfully created tunnel %s", tunnel_name)
        except Exception as e:
            # robust
            logging.error("Failed to create tunnel %s: %s", tunnel_name, str(e))
            raise


    def _destroy_tunnel(self, reg_req_packet):
        """Destroy GRE tunnel for given RegRequestPacket."""

        tid = self._get_binding_id(reg_req_packet.home_address)
        _destroy_interface(name="haip"+str(tid))


    def _send_packet(self, packet, addr):
        """Send packet to given address."""

        logging.info("Sending: %s", packet)
        self._socket.sendto(packet.to_data(), addr)


    def _check_flags(self, flags):
        """Return True, if given flags are supported."""

        # Flags verification. Some capabilities are not implemented yet...
        # Only co-located care-of address are supported, so
        # D flag (Decapsulation by mobile node) is mandatory.
        # S (Simultaneous bindings) and B (Broadcast datagrams) are
        # not supported.
        # Only GRE tunnel is supported, so G is mandatory and M is not allowed.
        is_ok = True
        if not flags & RegRequestPacket.FLAG_D:
            logging.warning("D flag is not set but is mandatory.")
            is_ok = False
        if flags & RegRequestPacket.FLAG_S:
            logging.warning("S flag is set but is not supported.")
            is_ok = False
        if flags & RegRequestPacket.FLAG_B:
            logging.warning("B flag is set but is not supported.")
            is_ok = False
        if not flags & RegRequestPacket.FLAG_G:
            logging.warning("G flag is not set but is mandatory.")
            is_ok = False
        if flags & RegRequestPacket.FLAG_M:
            logging.warning("M flag is set but is not supported.")
            is_ok = False
        return is_ok


    def _data_handler(self, data, addr):
        """Handle received data."""

        in_packet = Packet.from_data(data)

        logging.debug("Connected by: %s", addr)
        logging.debug("Received: %s", in_packet)
        #logging.debug("Extensions:")
        #for extension in in_packet.extensions:
        #    logging.info(extension)

        if not isinstance(in_packet, RegRequestPacket):
            logging.warning("Invalid packet type has been received. " +
                           "Discarding packet.")
            return

        # Registration Request received
        logging.info("Registration Request has been received.")
        logging.debug("Bindings table: %s" , self._print_binding_table())

        # MHAE verification
        mhae = in_packet.get_mhae()
        if mhae is None or mhae.spi not in self.auth_table:
            # Can't find matching SPI, so silently discarding
            logging.warning("Can't find matching SPI in request. " +
                            "Discarding request.")
            return
        key = self.auth_table[mhae.spi]
        if not in_packet.verify_mhae(mhae.spi, key):
            # Authorization failed
            logging.warning("Reqest authorization is failed.")
            # Sending Registration Reply
            out_packet = RegReplyPacket(
                RegReplyPacket.CODE_MN_FAILED_AUTH,
                0x0000,
                in_packet.home_address,
                in_packet.home_agent,
                in_packet.identification)
            out_packet.add_mhae(mhae.spi, key)
            self._send_packet(out_packet, addr)
            return

        # Determining if duplicate
        existing_reg_req_packet = self._get_binding(in_packet.home_address)
        if existing_reg_req_packet is not None:
            if (existing_reg_req_packet.identification == in_packet.identification
                and existing_reg_req_packet.care_of_address == in_packet.care_of_address):
                logging.warning("Request is a retransmission. " +
                                "Discarding request.")
                return

        # Timestamp verification
        ha_time = time.time()
        mn_time = ntp_to_system_time(in_packet.identification)
        if abs(int(ha_time-mn_time)) > self.max_ident_mismatch:
            # Registration ID mismatch
            logging.warning("Registration identification is mismatch.")
            out_packet = RegReplyPacket(
                RegReplyPacket.CODE_IDENT_MISMATCH,
                0x0000,
                in_packet.home_address,
                in_packet.home_agent,
                in_packet.identification)
            out_packet.add_mhae(mhae.spi, key)
            self._send_packet(out_packet, addr)
            return

        # Flags verification
        if not self._check_flags(in_packet.flags):
            out_packet = RegReplyPacket(
                RegReplyPacket.CODE_DENIED_BY_HA,
                0x0000,
                in_packet.home_address,
                in_packet.home_agent,
                in_packet.identification)
            out_packet.add_mhae(mhae.spi, key)
            self._send_packet(out_packet, addr)
            return

        # Addresses verification
        if in_packet.care_of_address == in_packet.home_address:
            logging.warning("Care-of address is the same as home address. " +
                            "Mobile node is in the home network.")
            if in_packet.lifetime > 0:
                logging.error("Mobile node is in the home network, " +
                              "but registration is requested.")
                # TODO: Perhaps request should be rejected...

        # Registration Request accepted
        logging.info("Registration Request is valid.")

        # Updatig lifetime if lifetime > max_lifetime
        if in_packet.lifetime > self.max_lifetime:
            logging.warning("Requested lifetime is greater than maximum.")
            in_packet.lifetime = self.max_lifetime

        # Creating or destroying binding
        if in_packet.lifetime > 0:
            # Registration
            self._create_binding(in_packet)
        else:
            # Deregistration
            logging.info("Deregistration is requested.")
            self._destroy_binding(in_packet)

        # Sending Registration Reply
        out_packet = RegReplyPacket(
            RegReplyPacket.CODE_ACCEPTED,
            in_packet.lifetime,
            in_packet.home_address,
            in_packet.home_agent,
            in_packet.identification)
        out_packet.add_mhae(mhae.spi, key)
        self._send_packet(out_packet, addr)


    def start(self):
        """Start Home Agent server."""

        if self._socket is not None:
            logging.warning("Home Agent is already started.")
            return

        try:
            _destroy_interfaces("mip")  # for mobile node interface
            _destroy_interfaces("haip") # for home agent interface
            os.system("sysctl -w net.ipv4.ip_forward=1")
        except Exception as e:
            logging.warning("Cleanup error: %s", str(e))

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((self.address, self.port))
        self._binding_checker.start()

        set_proxy_arp_for_all(True) # Enabling Proxy ARP
        set_ip_forward(True) # Enabling kernel IP forwarding

        logging.info("Home Agent is started.")
        while self._socket is not None:
            data, addr = self._socket.recvfrom(1024)
            self._data_handler(data, addr)


    def stop(self):
        """Stop Home Agent server."""

        self._stopping = True
        self._binding_checker.stop()

        _destroy_interfaces("mip")  # for mobile node interface
        _destroy_interfaces("haip") # for home agent interface
        set_ip_forward(False) # Disabling kernel IP forwarding
        set_proxy_arp_for_all(False) # Disabling Proxy ARP

        if self._socket is not None:
            self._socket.close()
            self._socket = None
            logging.info("Home Agent is stopped.")
        else:
            logging.warning("Home Agent is already stopped.")

