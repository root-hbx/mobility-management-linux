# Instance Usage

> Make sure you are under $mobility-management-linux when using these commands

```bash
# make sure
cd $mobility-management-linux
# activate .venv
source .venv/bin/activate
```

## Home Agent

* `home_agent.py` - HA implementation
* `ha.cfg` - HA configuration

**start HA service**

```bash
sudo $(which python3) -m examples.home_agent examples/ha.cfg
```

## Mobile Node

* `mn_agent.py` - MN implementation
* `mn.cfg` - MN configuration

**start MN service**

```bash
sudo $(which python3) -m examples.mn_agent start examples/mn.cfg
```

**stop MN service**

```bash
sudo $(which python3) -m examples.mn_agent stop examples/mn.cfg
```

**register with `eth0` interface**

```bash
sudo $(which python3) -m examples.mn_agent register eth0
```

**deregister**

```bash
sudo $(which python3) -m examples.mn_agent deregister
```

**get status info**

```bash
sudo $(which python3) -m examples.mn_agent status
```
