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
"""Mobile IP Mobile Node agent"""

import logging
import ast
import sys
import socket

import configparser as cparser
from classes import mip_components as comp

MGMT_PORT = 9907
stop = False # Stops app-loop if true
mn_agent = None


def start_app_loop():
    # App loop, waiting for mgmt command
    mgmt_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mgmt_socket.bind(("127.0.0.1", MGMT_PORT))
    while not stop:
        logging.debug("Waiting for management command.")
        data, addr = mgmt_socket.recvfrom(1024)
        resp = mgmt_data_handler(data)
        if resp is not None:
            mgmt_socket.sendto(resp, addr)


def mgmt_data_handler(data):
    if isinstance(data, bytes):
        data = data.decode('utf-8')
    logging.debug("Command '%s' has been received.", data)
    argv = data.split()

    if argv[0] == "stop":
        stop_mn_agent()
        return

    if argv[0] == "deregister":
        deregister()
        return

    if argv[0] == "cancel":
        cancel()
        return

    if argv[0] == "status":
        data = str(mn_agent.get_status())
        logging.debug("Status is: %s", data)
        data_byte = data.encode('utf-8')
        return data_byte

    if argv[0] == "register":
        if len(argv) < 2:
            logging.error("Interface name is required for registration.")
            return

        register(argv[1])
        return

    logging.error("Command '%s' is unknown.", argv[0])


def register(ifname):
    logging.info("Trying to register using %s interface.", ifname)
    try:
        mn_agent.register(
            ifname=ifname, 
            lifetime=1000,
            exception_handler=exception_handler
        )
    except comp.RegistrationFailed:
        logging.error("Registration has failed.")

def deregister():
    logging.info("Trying to deregister.")
    mn_agent.deregister(wait_for_reply=False)

def cancel():
    logging.info("Cancelling registration.")
    mn_agent.cancel()

def start_mn_agent(config_filename):
    global mn_agent

    logging.info("Starting Mobile Node Agent.")

    try:
        # Config file
        config = cparser.ConfigParser()
        config.read(config_filename)
        spi = config.getint("MobileNodeAgent","spi")
        key = config.get("MobileNodeAgent","key")
        home_agent = config.get("MobileNodeAgent","home_agent")
        home_address = config.get("MobileNodeAgent","home_address")
        if_gateways = ast.literal_eval(
            config.get("MobileNodeAgent","if_gateways"))

        # Creating mobile node agent object
        mn_agent = comp.MobileNodeAgent(
                    mhae_spi=spi, 
                    mhae_key=key,
                    home_agent=home_agent, 
                    home_address=home_address,
                    interfaces=if_gateways,
                    wait_for_dereg_reply=False,
                    flags=(comp.RegRequestPacket.FLAG_D | 
                        comp.RegRequestPacket.FLAG_G |
                        comp.RegRequestPacket.FLAG_T)
                )

        # App-loop, waiting for mgmt command
        start_app_loop()

    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        if mn_agent is not None:
            mn_agent.cancel()

def send_mgmt_command(data):
    logging.debug("Sending '%s' command.", data)
    mgmt_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data_bytes = data.encode('utf-8')
    mgmt_socket.sendto(data_bytes, ("127.0.0.1", MGMT_PORT))

    argv = data.split()
    if argv[0] == "status":
        logging.debug("Waiting for response.")
        recv_data, addr = mgmt_socket.recvfrom(1024)
        recv_str = recv_data.decode('utf-8')
        logging.debug("Received: %s", recv_str)
        return recv_str

def stop_mn_agent():
    global stop
    logging.info("Stopping Mobile Node Agent.")
    stop = True

def exception_handler(e):
    global stop
    logging.error("Error: %s", e)
    stop = True

def main(argv):
    if len(argv) < 1:
        # warning
        logging.critical("No arguments is provided.")
        # hints for args
        logging.critical("Please use one of the following commands:")
        logging.critical("  start <config_file>  - Start Mobile Node with a specified config file")
        logging.critical("  stop                 - Stop a running Mobile Node")
        logging.critical("  register <interface> - Register with specified network interface")
        logging.critical("  deregister           - Deregister from Home Agent")
        logging.critical("  cancel               - Cancel current registration process")
        logging.critical("  status               - Display current agent status")
        logging.critical("Example: sudo $(which python3) -m examples.mn_agent start examples/mn.cfg")
        return

    if argv[0] == "start":
        if len(argv) < 2:
            logging.critical("Config file is not provided.")
            logging.critical("Please start the node with a specified config file.")
            logging.critical("Example: sudo $(which python3) -m examples.mn_agent start examples/mn.cfg")
            return
        start_mn_agent(argv[1])
        return

    send_mgmt_command(" ".join(argv))

if __name__ == "__main__":
    main(sys.argv[1:])

logging.debug("Exiting...")
