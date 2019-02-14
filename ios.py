##
## Extend default Napalm driver with customized get_ functions
## Make sure the folder "custom_napalm" is in your Python path
##

from napalm.ios.ios import IOSDriver
import re


class CustomIOSDriver(IOSDriver):
    """Custom NAPALM Cisco IOS Handler."""

    def _send_cli(self, cmd, configmode=False, running_config=False):
        """
            Send a cli command and return the result or an error code
            if configmode = True then the command will be executed in config mode
            if running_config = True then the full config will be returned if the command would fail
               useful for example "show run | section something" is not supported so then the result
               will be the full running_config
        """
        error = None
        result = None
        delay_factor = 2

        conn = self.device
        cmd_running_config = "show run"

        re_error = re.compile('^(?P<ERROR>\% .*)$')

        try:
            if configmode:
                result = conn.send_config_set(cmd)
            else:
                result = conn.send_command(cmd, delay_factor=delay_factor)

            for l in result.splitlines():
                m = re_error.match(l)
                if m:
                    error = m.groupdict()["ERROR"]
                    result = None
                    if running_config:
                        #log.debug("requested command failed - return full running config")
                        result, error = self._send_cli(cmd_running_config, running_config=False)
                    break
        except Exception as e:
            error = "Unknown connection error occurred"
            #log.exception(e)
        if result:
            #log.debug("CLI cmd '{}' = {}".format(cmd, result))
            pass
        if error:
            #log.error("CLI cmd '{}' failed = {}".format(cmd, error))
            pass
        return result, error


    def get_vty(self):
        """
            Return VTY related facts
            This will return something like:

            "napalm_vty": {
                "count": 27,
                "lastline": 30,
                "line": {
                    "0": {
                        "acl_in": "40",
                        "acl_out": "41",
                        "transport_input": [
                            "telnet",
                            "ssh"
                        ]
                    },
                    "1": {
                        "acl_in": "40",
                        "acl_out": "41",
                        "transport_input": [
                            "telnet",
                            "ssh"
                        ]
                    },
                    "2": {
                        "transport_input": [
                            "telnet",
                            "ssh"
                        ]
                    },
                    "3": {
                        "transport_input": [
                            "telnet",
                            "ssh"
                        ]
                    },
                    "4": {
                        "rotary": "30",
                        "transport_input": [
                            "none"
                        ]
                    },
                },
                "lines": [
                    0,
                    1,
                    2,
                    3,
                    4,
                ]
            },
        """
        vty = {
            "lines": [],
            "count": None,
            "lastline": None,
            "line": {}
        }

        # try to get detailed info from the running config
        result, error = self._send_cli("show runn | section line vty", running_config=True)
        if result:
            in_vty = []
            for l in result.splitlines():
                if l.startswith("line vty"):
                    data = l.split()
                    if len(data) == 3:
                        in_vty = [ int(data[-1]) ]
                    elif len(data) == 4:
                        in_vty = list(range(int(data[-2]), int(data[-1])+1))
                    else:
                        in_vty = []
                    if in_vty:
                        vty["lines"] = vty["lines"] + in_vty
                        vty["count"] = len(vty["lines"])
                        vty["lastline"] = vty["lines"][-1]
                        for lineid in in_vty:
                            vty["line"][lineid] = {}
                elif in_vty and l.startswith(" rotary"):
                    for lineid in in_vty:
                        vty["line"][lineid]["rotary"] = str(l.split()[-1])
                elif in_vty and l.startswith(" transport"):
                    for lineid in in_vty:
                        data = l.split()
                        if data[1] == "input":
                            vty["line"][lineid]["transport_input"] = l.split()[2:]
                        elif data[2] == "output":
                            vty["line"][lineid]["transport_output"] = l.split()[2:]
                elif in_vty and l.startswith(" access-class"):
                    for lineid in in_vty:
                        data = l.split()
                        if data[-1] == "in":
                            vty["line"][lineid]["acl_in"] = data[-2]
                        elif data[-1] == "out":
                            vty["line"][lineid]["acl_out"] = data[-2]
                elif in_vty and not l.startswith(" "):
                    in_vty = []

            return vty

        # if the above fails then get basic info based on "show line" output
        result, error = self._send_cli("show line | i VTY")
        if result:
            vty["lines"] = list(range(len(result.splitlines())))
            if len(vty["lines"]) > 0:
                vty["lastline"] = vty["lines"][-1]
                vty["count"] = len(vty["lines"])
                for lineid in vty["lines"]:
                    vty["line"][lineid] = {}

        return vty


    def get_ssh(self):
        """
            Get facts related to SSH and SSH rotary ports:
              - supported: True|False
              - enabled: True|False
              - version
              - scp: True|False
              - rotary:
                  supported: True|False
                  ports: [ (sshport, rotaryport) ]
        """
        ssh = {
            "enabled": None,
            "supported": None,
            "version": None,
            "scp": None,
            "rotary": {
                "supported": None,
                "ports": []
            }
        }

        result, error = self._send_cli("show ip ssh | i nabled")

        if result:
            ssh["enabled"] = True
            ssh["supported"] = True
        elif error:
            ssh["enabled"] = False
            ssh["supported"] = False
        else:
            ssh["enabled"] = False
            ssh["supported"] = True

        # test support for ip ssh rotary port, send a
        result, error = self._send_cli("no ip ssh port 2200 rotary 100", True)
        if error:
            ssh["rotary"]["supported"] = False
        else:
            ssh["rotary"]["supported"] = True
            result, error = self._send_cli("show runn | section rotary", running_config=True)
            if result:
                for l in result.splitlines():
                    if l.startswith("ip ssh port") and len(l.split()) == 6:
                        ssh["rotary"]["ports"].append( (int(l.split()[-3]), int(l.split()[-1])) )

        return ssh


    def get_aaa(self):
        """
            Get AAA related facts
        """
        aaa = {
            "enabled": None,
            "server_groups": { "supported": None, "groups": {} },
            "config": { "authentication": [], "authorization": [], "accounting": [] },
        }

        result, error = self._send_cli("no aaa group server tacacs+ TESTAAAGROUP1", True)
        if error:
            aaa["server_groups"]["supported"] = False
        else:
            aaa["server_groups"]["supported"] = True


        result, error = self._send_cli("show runn | section aaa", running_config=True)
        if not error:
            if result:
                aaa["enabled"] = False
            server_group = None
            for l in result.splitlines():
                if server_group and not l.startswith(" "):
                    server_group = None
                if l.startswith("aaa new-model"):
                    aaa["enabled"] = True
                    continue
                if l.startswith("aaa authentication"):
                    aaa["config"]["authentication"].append(l)
                    continue
                if l.startswith("aaa authorization"):
                    aaa["config"]["authorization"].append(l)
                    continue
                if l.startswith("aaa accounting"):
                    aaa["config"]["accounting"].append(l)
                    continue
                m = re.match(r'^aaa group server (?P<PROTO>\S+) (?P<GRP>\S+)$', l)
                if m:
                    server_group = m.groupdict()["GRP"]
                    aaa["server_groups"]["groups"][server_group] = { "protocol": m.groupdict()["PROTO"], "source-interface": None, "server": None, "vrf": None, "key": None }
                    continue
                if server_group and l.startswith(" ip vrf forwarding"):
                    aaa["server_groups"]["groups"][server_group]["vrf"] = l.split()[-1]
                    continue
                if server_group and l.startswith(" ip tacacs source-interface"):
                    aaa["server_groups"]["groups"][server_group]["source-interface"] = l.split()[-1]
                    continue
                if server_group and l.startswith(" server name "):
                    aaa["server_groups"]["groups"][server_group]["server"] = l.split()[-1]
                    continue
                if server_group and l.startswith(" key"):
                    aaa["server_groups"]["groups"][server_group]["key"] = l.split()[-1]
                    continue

        return aaa

    def get_tacacs(self):
        """
            Get facts related to tacacs:
              - check support for format "tacacs server <servername>"
              - check support for format "tacacs server <ip>"
              - reads tacacs related config out of running config
        """
        tacacs = {
            "supports_servernames": None,
            "supports_ip": None,
            "supports_newstyle": None,
            "servers": {},     # { "<server>": { "address": None, "key": None, "encrypted": None }  }
            "key": None,       #  { "key": None, "encrypted": None },
            "source-interface": None,
            "config": []
        }

        result, error = self._send_cli("no tacacs server TESTSERVER123", True)
        if error:
            tacacs["supports_servernames"] = False
            result, error = self._send_cli("no tacacs server 9.9.9.9", True)
            if error:
                tacacs["supports_ip"] = False
                tacacs["supports_newstyle"] = False
            else:
                tacacs["supports_ip"] = True
                tacacs["supports_newstyle"] = True
        else:
            tacacs["supports_newstyle"] = True
            tacacs["supports_servernames"] = True
            tacacs["supports_ip"] = True

        result, error = self._send_cli("show running-config | section tacacs", running_config=True)
        if not error:
            server_found = None
            for l in result.splitlines():
                if l.startswith("tacacs") or server_found:
                    if server_found and not l.startswith(" "):
                        server_found = None
                    if l.startswith("tacacs-server"):
                        tacacs["config"].append(l)
                    if l.startswith("tacacs server "):
                        server_found = l.split()[-1]
                        tacacs["servers"][server_found] = { "address": None, "key": None, "encrypted": None }
                        continue
                    m = re.match(r'^ key(?P<ENCR> [0-9])? (?P<KEY>\S+)$', l)
                    if m and server_found:
                        encr = True if "ENCR" in m.groupdict() else False
                        tacacs["servers"][server_found]["key"] = m.groupdict()["KEY"]
                        tacacs["servers"][server_found]["encrypted"] = encr
                        continue
                    m = re.match(r'^ address ipv4 (?P<ADDR>\S+)$', l)
                    if m and server_found:
                        tacacs["servers"][server_found]["address"] = m.groupdict()["ADDR"]
                        continue
                    m = re.match(r'^tacacs-server host (?P<HOST>\S+)(?: key(?P<ENCR> [0-9])? (?P<KEY>\S+))?$', l)
                    if m:
                        key = m.groupdict().get("KEY", None)
                        encr = True if key and m.groupdict().get('ENCR', None) else False
                        tacacs["servers"][m.groupdict()["HOST"]] = { "address": m.groupdict()["HOST"], "key": key, "encrypted": encr }
                        continue
                    m = re.match(r'^tacacs-server key(?P<ENCR> [0-9])? (?P<KEY>\S+)$', l)
                    if m:
                        encr = True if "ENCR" in m.groupdict() else False
                        tacacs["key"] = { "key": m.groupdict()["KEY"], "encrypted": encr }
                        continue
                if l.startswith("ip tacacs source-interface"):
                    tacacs["source-interface"] = l.split()[-1]

        return tacacs


    def get_extended_facts(self):
        """
            Get extended facts from a cisco IOS device.
            Some facts can only be found by performing a test in config mode, keep in mind that this is slow.
        """
        extended_facts = {
            "connection": {
                "hostname": self.hostname,  # hostname used to connect to the device
                "username": self.username,
                "transport": self.transport,
                "port": self.netmiko_optional_args.get('port', None),
                "profile": self.profile,
                "device_type": self.device.device_type
            }
        }

        extended_facts['dns'] = self.get_dns()
        extended_facts['iphelpers'] = self.get_iphelpers()
        extended_facts['logging'] = self.get_logging()
        extended_facts['tacacs'] = self.get_tacacs()
        extended_facts['aaa'] = self.get_aaa()
        extended_facts['ssh'] = self.get_ssh()
        extended_facts['vty'] = self.get_vty()

        return extended_facts


    def get_dns(self):
        """
            Get information related to name resolving
        """
        dns = {
            "domain_name": None,    # configured domain-name
            "domain_lookup": True,
            "supports_local_hosts": None,
            "name_servers": [],
            "local_hosts": []
        }

        rexHosts = re.compile("^(?P<hostname>\w+) .* (?P<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$")

        result, error = self._send_cli("no ip host TESTSERVER 1.2.3.4", True)
        if error:
            dns["supports_local_hosts"] = False
        else:
            dns["supports_local_hosts"] = True

        result, error = self._send_cli("show runn all | i ip domain")
        if not error:
            for l in result.splitlines():
                m = re.match(r'^(?P<NO>no )?ip domain lookup', l)
                if m:
                    if "NO" in m.groupdict():
                        dns["domain_lookup"] = False
                        continue
                m = re.match(r'ip domain[- ]name (?P<NAME>\S+)', l)
                if m:
                    dns["domain_name"] = m.groupdict()["NAME"]
                    continue
                if l.startswith("ip name"):
                    dns["name_servers"].append(l.split()[-1])
                    continue

        result, error = self._send_cli("show hosts")
        for l in result.splitlines():
            ## only use the lines that end with a valid IP address
            m = rexHosts.match(l)
            if m:
                dns["local_hosts"].append({ "hostname": m.groupdict()["hostname"], "ip": m.groupdict()["ip"] })

        return dns


    def get_iphelpers(self):
        """
            Parse "show ip helpers"
            {
                '<interface>': [ <ip helper> ]
            }
        """
        iphelpers = {}
        rexIP = re.compile('.*[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*')

        result, error = self._send_cli("show ip helper", False)
        if not error:
            colcnt = None
            interface = None
            for l in result.splitlines():
                if not rexIP.match(l):
                    continue
                row = l.split()
                ip = None
                if not row[0][0].isdigit():
                    interface = row[0]
                    ip = row[1]
                    iphelpers[interface] = []
                else:
                    ip = row[0]
                if interface:
                    iphelpers[interface].append(ip)
        return iphelpers


    def get_logging(self):
        """
            Parse "show log"
            {
              level: "",
              hosts: [
                {
                  "host": <host>
                }
              ]
            }
        """
        log = {
            "trap_loglevel": None,
            "syslog_enabled": None,
            "hosts": []
        }

        command = 'show logging'
        output = self._send_command(command)

        rexHost = re.compile("^.*Logging to (?P<HOST>\S+) .*$")
        rexSyslogEnabled = re.compile("^.*Syslog logging: (?P<SYSLOG_STATE>\S+) .*$")
        rexTraplevel = re.compile("^.*Trap logging: level (?P<TRAPLOGLEVEL>\S+) .*$")

        for line in output.splitlines():
            if 'ogging' in line:
                m = rexHost.match(line)
                if m:
                    log["hosts"].append(m.groupdict()["HOST"])
                    continue
                m = rexSyslogEnabled.match(line)
                if m:
                    log["syslog_enabled"] = True if 'enabled' in m.groupdict()["SYSLOG_STATE"] else False
                    continue
                m = rexTraplevel.match(line)
                if m:
                    log["trap_loglevel"] = m.groupdict()["TRAPLOGLEVEL"]

        return log



    def get_my_banner(self):
        """
            Some example function
        """
        command = 'show banner motd'
        output = self._send_command(command)

        return_vars = {}
        for line in output.splitlines():
            split_line = line.split()
            if "Site:" == split_line[0]:
                return_vars["site"] = split_line[1]
            elif "Device:" == split_line[0]:
                return_vars["device"] = split_line[1]
            elif "Floor:" == split_line[0]:
                return_vars["floor"] = split_line[1]
            elif "Room:" == split_line[0]:
                return_vars["room"] = split_line[1]
        return return_vars



    def get_netflow(self):
        flow = {
            "enabled": None,
            "supported": None,
            "version": None,
            "timeout-active": None,
            "timeout-inactive": None,
            "interfaces": [],
            "destinations": []
        }

        re_enabled = re.compile(r'^.* export (?P<VERSION>v[0-9]) is (?P<STATE>enabled|disabled) .*')
        re_src = re.compile(r'^.*Source\((?P<INDEX>[0-9]+)\) +(?P<SRCIP>[^ ]+) \((?P<SRCINT>.*)\).*')
        re_dest = re.compile(r'^.*Destination\((?P<INDEX>[0-9]+)\) +(?P<DSTIP>[^ ]+) \((?P<DSTPORT>[0-9]+)\).*')

        result, error = self._send_cli("show ip flow interface")
        if not error:
            flow["supported"] = True
            if result:
                flow["enabled"] = True
            intf = None
            for l in result.splitlines():
                if l and not l.startswith(" "):
                    if intf:
                        flow["interfaces"].append(intf)
                    intf = { "interface": l, "ingress": False, "egress": False }
                elif l and l.startswith(" "):
                    if intf:
                        if "ingress" in l:
                            intf["ingress"] = True
                        elif "egress" in l:
                            intf["egress"] = True
            if intf:
                flow["interfaces"].append(intf)


        result, error = self._send_cli("show ip cache flow")
        if not error:
            for l in result.splitlines():
                if "Active flows timeout" in l:
                    flow["timeout-active"] = l.split(" ")[-2]
                elif "Inactive flows timeout" in l:
                    flow["timeout-inactive"] = l.split(" ")[-2]


        result, error = self._send_cli("show ip flow export")
        if not error:
            destinations = []
            vrf = None
            for l in result.splitlines():
                if l and not l.startswith(" "):
                    m = re_enabled.match(l)
                    if m:
                        flow["enabled"] = True if m.groupdict()["STATE"] == "enabled" else False
                        flow["version"] = m.groupdict()["VERSION"]
                        continue
                if l and "VRF ID" in l:
                    vrf = l.split(" ")[-1]
                    continue
                if l and "Source" in l:
                    m = re_src.match(l)
                    if m:
                        d = { "index": m.groupdict()["INDEX"],
                              "srcip": m.groupdict()["SRCIP"],
                              "srcint": m.groupdict()["SRCINT"],
                              "vrf": vrf,
                              "dstip": None,
                              "dstport": None
                            }
                        destinations.append(d)
                    continue
                if l and "Destination" in l:
                    m = re_dest.match(l)
                    if m:
                        d = [ x for x in destinations if x["index"] == m.groupdict()["INDEX"]]
                        if d:
                            d = d[0]
                            d["dstip"] = m.groupdict()["DSTIP"]
                            d["dstport"] = m.groupdict()["DSTPORT"]
                        continue
            if destinations:
                flow["destinations"] = destinations

        return flow



