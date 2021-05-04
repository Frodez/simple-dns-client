#ifndef UTIL_H
#define UTIL_H

#include "portable/portable_dns.h"
#include "portable/portable_endian.h"

#include <condition_variable>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <regex>
#include <tuple>
#include <vector>

namespace dns {

class result {
private:
    uint8_t code;
    std::string msg;
    result(uint8_t code, std::string&& msg);

public:
    const std::string& message();
    [[nodiscard]] bool is_ok() const;
    static result ok();
    static result error(std::string&& msg);
};

result::result(uint8_t code, std::string&& msg)
    : code { code }
    , msg { msg }
{
}

const std::string& result::message()
{
    return msg;
}

bool result::is_ok() const
{
    return code == 0;
}

result result::ok()
{
    return { 0, "ok" };
}

result
result::error(std::string&& msg = "")
{
    return { 1, std::move(msg) };
}

std::string uint8_to_string(uint8_t num)
{
    static const std::string table[256] = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11",
        "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27",
        "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43",
        "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59",
        "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75",
        "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91",
        "92", "93", "94", "95", "96", "97", "98", "99", "100", "101", "102", "103", "104", "105", "106",
        "107", "108", "109", "110", "111", "112", "113", "114", "115", "116", "117", "118", "119", "120",
        "121", "122", "123", "124", "125", "126", "127", "128", "129", "130", "131", "132", "133", "134",
        "135", "136", "137", "138", "139", "140", "141", "142", "143", "144", "145", "146", "147", "148",
        "149", "150", "151", "152", "153", "154", "155", "156", "157", "158", "159", "160", "161", "162",
        "163", "164", "165", "166", "167", "168", "169", "170", "171", "172", "173", "174", "175", "176",
        "177", "178", "179", "180", "181", "182", "183", "184", "185", "186", "187", "188", "189", "190",
        "191", "192", "193", "194", "195", "196", "197", "198", "199", "200", "201", "202", "203", "204",
        "205", "206", "207", "208", "209", "210", "211", "212", "213", "214", "215", "216", "217", "218",
        "219", "220", "221", "222", "223", "224", "225", "226", "227", "228", "229", "230", "231", "232",
        "233", "234", "235", "236", "237", "238", "239", "240", "241", "242", "243", "244", "245", "246",
        "247", "248", "249", "250", "251", "252", "253", "254", "255" };
    return table[num];
}

char uint4_to_char(uint8_t num)
{
    static const char table[16] = { '0', '1', '2', '3', '4', '5',
        '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    num = num & 0x0f;
    return table[num];
}

std::vector<std::string> get_sys_default_servers()
{
#if (defined(__WINDOWS__) && !defined(__MINGW64__))
//https://docs.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getnetworkparams
#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
    std::vector<std::string> res {};
    FIXED_INFO* pFixedInfo = (FIXED_INFO*)MALLOC(sizeof(FIXED_INFO));
    ULONG ulOutBufLen = sizeof(FIXED_INFO);
    DWORD dwRetVal;
    IP_ADDR_STRING* pIPAddr;
    if (pFixedInfo == NULL) {
        throw std::runtime_error { "Error allocating memory needed to call GetNetworkParams\n" };
    }
    if (GetNetworkParams(pFixedInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        FREE(pFixedInfo);
        pFixedInfo = (FIXED_INFO*)MALLOC(sizeof(FIXED_INFO));
        if (pFixedInfo == NULL) {
            throw std::runtime_error { "Error allocating memory needed to call GetNetworkParams\n" };
        }
    }
    if (dwRetVal = GetNetworkParams(pFixedInfo, &ulOutBufLen) != NO_ERROR) {
        std::string error { "GetNetworkParams failed with error:" };
        error.append(std::to_string(dwRetVal));
        throw std::runtime_error { error };
    }
    res.push_back(std::move(std::string { pFixedInfo->DnsServerList.IpAddress.String }));
    pIPAddr = pFixedInfo->DnsServerList.Next;
    while (pIPAddr) {
        res.push_back(std::move(std::string { pIPAddr->IpAddress.String }));
        pIPAddr = pIPAddr->Next;
    }
    return res;
#else
    std::vector<std::string> result {};
    res_init();
    for (int i = 0; i != _res.nscount; i++) {
        std::string server {};
        sockaddr_in& a = _res.nsaddr_list[i];
        if (a.sin_family == AF_INET) {
            uint32_t& b = a.sin_addr.s_addr;
            uint8_t byte = b & 0xff;
            server.append(uint8_to_string(byte));
            server.push_back('.');
            byte = (b >> 8) & 0xff;
            server.append(uint8_to_string(byte));
            server.push_back('.');
            byte = (b >> 16) & 0xff;
            server.append(uint8_to_string(byte));
            server.push_back('.');
            byte = (b >> 24) & 0xff;
            server.append(uint8_to_string(byte));
        }
        result.push_back(server);
    }
    return result;
#endif
}

bool is_valid_domain_name(const std::string& domain)
{
    //https://www.geeksforgeeks.org/how-to-validate-a-domain-name-using-regular-expression/
    static const std::regex pattern { "^(?!-)[A-Za-z0-9-]+([\\-\\.]{1}[a-z0-9]+)*\\.[A-Za-z]{2,6}$" };
    return !domain.empty() && std::regex_match(domain, pattern);
}

bool is_valid_ipv4_addr(const std::string& addr)
{
    //https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    static const std::regex pattern { "((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.)"
                                      "{3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])" };
    return !addr.empty() && std::regex_match(addr, pattern);
}

bool is_valid_ipv6_addr(const std::string& addr)
{
    //https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
    static const std::regex pattern { "(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
                                      "([0-9a-fA-F]{1,4}:){1,7}:|"
                                      "([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
                                      "([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
                                      "([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
                                      "([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
                                      "([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
                                      "[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
                                      ":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
                                      "fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
                                      "::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|"
                                      "1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|"
                                      "1{0,1}[0-9]){0,1}[0-9])|"
                                      "([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|"
                                      "(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|"
                                      "(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))" };
    return !addr.empty() && std::regex_match(addr, pattern);
}

uint8_t read_uint8(uint8_t* buf)
{
    return buf[0];
}

void write_uint8(uint8_t* buf, uint8_t b)
{
    buf[0] = b;
}

uint16_t read_uint16(const uint8_t* buf)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return ((uint16_t)buf[0]) << 8 | ((uint16_t)buf[1]);
#elif __BYTE_ORDER == __BIG_ENDIAN
    return ((uint16_t)buf[1]) << 8 | ((uint16_t)buf[0]);
#else
#error "Unknown byte order"
#endif
}

void write_uint16(uint8_t* buf, uint16_t b)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    buf[0] = (b >> 8) & 0xFF;
    buf[1] = b & 0xFF;
#elif __BYTE_ORDER == __BIG_ENDIAN
    buf[1] = (b >> 8) & 0xFF;
    buf[0] = b & 0xFF;
#else
#error "Unknown byte order"
#endif
}

uint32_t read_uint32(const uint8_t* buf)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return ((uint32_t)buf[0]) << 24 | ((uint32_t)buf[1]) << 16 | ((uint32_t)buf[2]) << 8 | ((uint32_t)buf[3]);
#elif __BYTE_ORDER == __BIG_ENDIAN
    return ((uint32_t)buf[3]) << 24 | ((uint32_t)buf[2]) << 16 | ((uint32_t)buf[1]) << 8 | ((uint32_t)buf[0]);
#else
#error "Unknown byte order"
#endif
}

void write_uint32(uint8_t* buf, uint32_t b)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    buf[0] = (b >> 24) & 0xFF;
    buf[1] = (b >> 16) & 0xFF;
    buf[2] = (b >> 8) & 0xFF;
    buf[3] = b & 0xFF;
#elif __BYTE_ORDER == __BIG_ENDIAN
    buf[3] = (b >> 24) & 0xFF;
    buf[2] = (b >> 16) & 0xFF;
    buf[1] = (b >> 8) & 0xFF;
    buf[0] = b & 0xFF;
#else
#error "Unknown byte order"
#endif
}

void read_bytes(uint8_t* buf, uint8_t* dest, size_t bytes_per_unit, size_t units)
{
    if (bytes_per_unit == 0 || units == 0) {
        return;
    }
    if (bytes_per_unit == 1) {
        memcpy(dest, buf, units);
        return;
    }
    size_t pos_unit = 0;
    while (pos_unit != units) {
        size_t offset = pos_unit * bytes_per_unit;
        size_t inner_index = 0;
        while (inner_index != bytes_per_unit) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
            dest[offset + bytes_per_unit - 1 - inner_index] = buf[offset + inner_index];
#elif __BYTE_ORDER == __BIG_ENDIAN
            dest[offset + inner_index] = buf[offset + inner_index];
#else
#error "Unknown byte order"
#endif
            inner_index++;
        }
        pos_unit++;
    }
}

void write_bytes(uint8_t* buf, uint8_t* src, size_t bytes_per_unit, size_t units)
{
    if (bytes_per_unit == 0 || units == 0) {
        return;
    }
    if (bytes_per_unit == 1) {
        memcpy(buf, src, units);
        return;
    }
    size_t pos_unit = 0;
    while (pos_unit != units) {
        size_t offset = pos_unit * bytes_per_unit;
        size_t inner_index = 0;
        while (inner_index != bytes_per_unit) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
            buf[offset + bytes_per_unit - 1 - inner_index] = src[offset + inner_index];
#elif __BYTE_ORDER == __BIG_ENDIAN
            buf[offset + inner_index] = src[offset + inner_index];
#else
#error "Unknown byte order"
#endif
            inner_index++;
        }
        pos_unit++;
    }
}

}

#endif