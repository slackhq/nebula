#!/usr/bin/python


class FilterModule(object):
    def filters(self):
        return {
            'to_nebula_ip': self.to_nebula_ip,
            'map_to_nebula_ips': self.map_to_nebula_ips,
        }

    def to_nebula_ip(self, ip_str):
        ip_list = list(map(int, ip_str.split(".")))
        ip_list[0] = 10
        ip_list[1] = 168
        ip = '.'.join(map(str, ip_list))
        return ip

    def map_to_nebula_ips(self, ip_strs):
        ip_list = [ self.to_nebula_ip(ip_str) for ip_str in ip_strs ]
        ips = ', '.join(ip_list)
        return ips
