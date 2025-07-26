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
"""Mobile IP Home Agent"""

import logging
import ast
import sys
import os

import configparser as cparser
from classes import mip_components as comp

home_agent = None


def start_home_agent(config_filename):
    global home_agent

    logging.info("Starting Home Agent.")
    
    # This program requires root privileges
    if os.geteuid() != 0:
        logging.error("This program requires root privileges to run.")
        logging.error("Please run with sudo or as root.")
        sys.exit(1)
    '''
    - os.geteuid() returns the effective user ID of the current process.
    - root's effective user ID is 0.
    '''

    try:
        # Config file
        config = cparser.ConfigParser()
        config.read(config_filename)
        address = config.get("HomeAgent","address")
        auth_table = ast.literal_eval(config.get("HomeAgent","auth_table"))
        # TODO(bxhu): need to check if address is valid IP address

        logging.debug("HA address: %s", address)
        logging.debug("HA authentications: %s", auth_table)

        # Creating and staring home agent object
        home_agent = comp.HomeAgent(address=address, auth_table=auth_table)
        home_agent.start()

        # Endless running
        while True:
            pass
    except (KeyboardInterrupt, SystemExit, comp.Error):
        logging.info("Exiting...")
        home_agent.stop()
    finally:
        if home_agent is not None:
            home_agent.stop()


def main(argv):
    if len(argv) < 1:
        logging.critical("Config file is not provided.")
        logging.critical("Please start the node with a specified config file.")
        logging.critical("Example: sudo $(which python3) -m examples.home_agent start examples/ha.cfg")
        return

    start_home_agent(argv[0])


if __name__ == "__main__":
    main(sys.argv[1:])
