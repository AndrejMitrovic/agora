module agora.utils.InetUtils;

import agora.utils.Log;

import std.algorithm;
import std.algorithm.searching;
import std.array;
import std.conv;
import std.socket;

import core.stdc.string;

mixin AddLogger!();

struct InetUtils
{
version(OSX){

import core.sys.linux.ifaddrs;
import core.sys.posix.netdb;

    public static string[] get_all_ips()
    {
        return [];
    }
}
version(linux){

import core.sys.linux.ifaddrs;
import core.sys.posix.netdb;

    public static string[] get_all_ips()
    {
        string[] ips = [];

        ifaddrs *if_address_head_poi;
        ifaddrs *if_address_poi;

        getifaddrs (&if_address_head_poi);
        scope(exit) freeifaddrs(if_address_head_poi);

        for (if_address_poi = if_address_head_poi; if_address_poi; if_address_poi = if_address_poi.ifa_next)
        {
            if (if_address_poi.ifa_addr &&
            (if_address_poi.ifa_addr.sa_family==AF_INET || if_address_poi.ifa_addr.sa_family==AF_INET6))
            {
                const ipv6 = if_address_poi.ifa_addr.sa_family==AF_INET6;
                const sockaddr_len  = ipv6? sockaddr_in6.sizeof : sockaddr_in.sizeof;

                char[NI_MAXHOST] buffer;
                int name_info_res = getnameinfo(
                                if_address_poi.ifa_addr,
                                sockaddr_len,
                                buffer.ptr,
                                buffer.length,
                                null,
                                0,
                                NI_NUMERICHOST);
                if (name_info_res)
                {
                    log.error("error happened during a call to getnameinfo, name_info_res code:", name_info_res);
                    continue;
                }
                string ip = buffer[0 .. strlen(buffer.ptr)].idup();
                ips ~= ip;
            }
        }

        return ips;
    }
}
version(Windows)
{

import std.socket;

import core.sys.windows.iphlpapi;
import core.sys.windows.iptypes;
import core.sys.windows.windef;
import core.sys.windows.winsock2;
import core.stdc.stdlib: malloc, free;
import core.stdc.string: strlen;

    public static string[] get_all_ips()
    {
        string[] ips = [];
        PIP_ADAPTER_INFO adapter_info_head;
        PIP_ADAPTER_INFO adapter_info;
        DWORD ret_adapters_info;
        ULONG buff_length = IP_ADAPTER_INFO.sizeof;
        adapter_info_head = cast(IP_ADAPTER_INFO *) malloc(IP_ADAPTER_INFO.sizeof);
        if (adapter_info_head == NULL)
        {
            log.error("Error allocating memory needed to call GetAdaptersinfo - 1");
            return [];
        }
        scope(exit) free(adapter_info_head);
        // find out the real size we need to allocate
        if (GetAdaptersInfo(adapter_info_head, &buff_length) == ERROR_BUFFER_OVERFLOW)
        {
            free(adapter_info_head);
            adapter_info_head = cast(IP_ADAPTER_INFO *) malloc(buff_length);
            if (adapter_info_head == NULL)
            {
                log.error("Error allocating memory needed to call GetAdaptersinfo - 2");
                return [];
            }
        }
        if ((ret_adapters_info = GetAdaptersInfo(adapter_info_head, &buff_length)) == NO_ERROR) {
            adapter_info = adapter_info_head;
            while (adapter_info)
            {
                auto ip_tmp = cast(char *) adapter_info.IpAddressList.IpAddress.String;
                string ip = ip_tmp[0 .. strlen(ip_tmp)].idup;
                if(!ip.length || ip == "0.0.0.0")
                {
                    adapter_info = adapter_info.Next;
                    continue;
                }
                ips ~= ip;
                adapter_info = adapter_info.Next;
            }
        }
        else
        {
            log.error("GetAdaptersInfo failed with error: {}", ret_adapters_info);
        }
        return ips;
    }
}

    public static string[] get_all_public_ips()
    {
        return filter_ips(ip => !is_private_ip(ip));
    }

    public static string[] get_all_private_ips()
    {
        return filter_ips(&is_private_ip);
    }

    private static bool is_private_ip(string ip)
    {
        bool is_ipv6 = ip.canFind(':');
        if(is_ipv6)
        {
            if(ip == "" || ip == "::" || "::1") // Loopback
                return true;
            ushort[] ip_parts = ip.split("::").map!(ip_part => to!ushort(ip_part,16)).array();
            if(ip_parts.length >= 1)
            {
                if(ip_parts[0] >= to!ushort("fe80",16) && ip_parts[0] <= to!ushort("febf",16)) // Link
                    return true;
                if(ip_parts[0] >= to!ushort("fc00",16) && ip_parts[0] <= to!ushort("fdff",16)) // Private network
                    return true;
                if(ip_parts[0] == to!ushort("100",16)) // Discard prefix
                    return true;
            }
            return false;
        }
        else
        {
            // private and loopback addresses are the followings
            // 10.0.0.0    - 10.255.255.255
            // 172.16.0.0  - 172.31.255.255
            // 192.168.0.0 - 192.168.255.255
            // 169.254.0.0 - 169.254.255.255
            // 127.0.0.0   - 127.255.255.255

            ubyte[] ip_parts = ip.split(".").map!(ip_part => to!ubyte(ip_part)).array();
            return
                (ip_parts[0]==10) ||
                ((ip_parts[0]==172) && (ip_parts[1]>=16 && ip_parts[1]<=31)) ||
                (ip_parts[0]==192 && ip_parts[1]==168) ||
                (ip_parts[0]==169 && ip_parts[1]==254) ||
                (ip_parts[0]==127);

        }
    }

    private static string[] filter_ips(bool function(string ip) filter_func)
    {
        return filter!(ip => filter_func(ip))(get_all_ips()).array();
    }

}
