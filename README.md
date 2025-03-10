# Mobility Management Simulator

> aka. MM-Sim

- Mobility Management
- Mobile IP: MIPv4

Partial implementation of [RFC 5944](https://tools.ietf.org/html/rfc5944) Mobile IP framework for Linux Ubuntu 22.04LTS, written in Python 3.10.

---

🔥 *News* 🔥

- [2025-0311] All functions (`start/stop/register/deregister/status`) are ready to go!
- [2025-0310] Refactor! Refactor! Refactor!
- [2025-0309] MM-Sim is supporting Ubuntu 22.04 LTS and Python 3.10

## Overview

🚀 Mobile IP (MIP) framework allows transparent routing of IP packets to mobile nodes regardless of its current point of attachment in a the Internet. Thanks to MIP, mobile node is able to roam from an its home network to any foreign network, being always reachable through its home IP address.

🌟 A brief introduction of Mobile IP is provided [here](https://docs.google.com/presentation/d/1uMKtgEIESeQTkul_gu7KrXnIFI3lo5WVHKnhKJMQ3ag/edit?usp=drive_link)

🎉 Following key features are supported:

* Mobile IP protocol (Registration Request and Reply)
* Mobile-Home Authentication Extension (MHAE) with  the 128-bit key `HMAC-MD5` authentication algorithm
* Home Agent entity
* Mobile Node entity
* Co-located CoA mode
* Forward and Reverse tunneling
* GRE encapsulation
* Identification based on timestamp

⚠️ Following key features are not supported:

* Agent discovery and advertisement with ICMP
* Foreign Agent entity
* Minimal encapsulation
* Broadcast datagrams

Basic use case that can be achieved with this implementation of MIP is shown on figure below.

![](./doc/drawing.png)

## Quick Start

**Create a venv**

```sh
# create a venv with py3.10
python -m venv .venv
# activate
source .venv/bin/activate
```

**Dependencies**

```bash
# plz make sure you are under a python venv
pip install ntplib pyroute2 netaddr
```

**Start for HA and MN**

```bash
cd mobility-management-linux
# HOME AGENT: with sudo privilege!!!
sudo $(which python3) -m examples.home_agent examples/ha.cfg
# MOBILE NODE: with sudo privilege!!!
# start
sudo $(which python3) -m examples.mn_agent start examples/mn.cfg
# Other args like: stop / register / deregister ...
```

Congratulates! 👍

More commands for HA and MN can be checked [here](./examples/README.md).

## Related Work

This repo is inspired by [mkiol's Mobile IP](https://github.com/mkiol/MobileIP) 🫡

This project, developed by [Boxuan Hu](https://bxhu2004.com/), rectifies errors in previous work and upgrades the entire project from Python 2 to Python 3, incorporating a comprehensive restructuring. 🚀

Modifications and additions are licensed under [MIT-License](https://en.wikipedia.org/wiki/MIT_License). For details on what changes were made, please refer to the commit history.

The project is currently stable on Linux Ubuntu 22.04 LTS and supports Python 3.10. 🌟

