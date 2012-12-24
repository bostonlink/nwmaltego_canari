nwmaltego_canari - Netwitness Maltego Integration Canari Package
=================================================================

Author: David Bressler (@bostonlink)

## 1.0 - About

nwmaltego_canari is a port of the NWmaltego project into a canari framework package.  The reason for the port is to
make installing, using, and modifying the nwmaltego transforms much easier.  The Canari framework is a Maltego local
transform framework created for rapid development and deployment of Maltego transforms.

The NWmaltego project is a project that integrates searching Netwitness network session metadata into Maltego transforms.
The project is used to graphically map out network investigations within netwitness to a Maltego graph.  This helps,
security teams, investigators, incident responders, etc.

* `src/nwmaltego_canari` directory is where all modules are stored
* `src/nwmaltego_canari/transforms` directory is where all nwmaltego transforms are stored
* `src/nwmaltego_canari/transforms/common` directory is where the nwmodule is stored and is a NW REST API wrapper
* `src/nwmaltego_canari/transforms/common/entities.py` is where all nwmaltego custom entities are defined
* `maltego/` is where the Maltego entity exports are stored.
* `src/nwmaltego_canari/resources/maltego` directory is where the `entities.mtz` files are stored for auto
  install and uninstall.

## 2.0 - Installation

### 2.1 - Supported Platforms
nwmaltego_canari has currently been tested on Mac OS X and Linux.
Further testing will be done on Windows in the near future.

### 2.2 - Requirements
nwmaltego_canari is supported and tested on Python 2.7.3
The canari framework must be installed to use this package
See: https://github.com/allfro/canari

### 2.3 - How to install
Once you have the Canari framework installed and working, follow the directions below to install nwmaltego_canari

Before installing the nwmaltego canari package you must edit the nwmaltego_canari.conf file with the prropriate credentials
and netwitness information such as hostname/ip address and REST API URL.  Then you can install the package and go to town!

Install the package:

```bash
$ cd nwmaltego_canari
$ python setup.py install
```
Then install the canari package by issuing the following:

```bash
$ canari install-package nwmaltego_canari
```

# Special Thanks!

Rich Popson (@Rastafari0728)<br/>
Nadeem Douba (@ndouba)<br/>
Paterva (@Paterva)<br/>
MassHackers (@MassHackers)<br/>



