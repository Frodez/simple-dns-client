#ifndef DNS_MSG_H
#define DNS_MSG_H

#include "dns_rfc.h"
#include "dns_util.h"

#include <cstddef>
#include <cstring>
#include <fmt/core.h>
#include <memory>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace dns {

typedef std::tuple<std::shared_ptr<uint8_t[]>, size_t> packet_type;

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    uint16_t get_qr()
    {
        return (flags & 0x8000) >> 15;
    }
    uint16_t get_opcode()
    {
        return (flags & 0x7800) >> 11;
    }
    uint16_t get_aa()
    {
        return (flags & 0x0400) >> 10;
    }
    uint16_t get_tc()
    {
        return (flags & 0x0200) >> 9;
    }
    uint16_t get_rd()
    {
        return (flags & 0x0100) >> 8;
    }
    uint16_t get_ra()
    {
        return (flags & 0x0080) >> 7;
    }
    uint16_t get_zero()
    {
        return (flags & 0x0070) >> 4;
    }
    uint16_t get_rcode()
    {
        return flags & 0x000F;
    }
    std::string to_string();
    std::string to_json_string();
};

std::string dns_header::to_string()
{
    uint16_t qr = get_qr();
    uint16_t opcode = get_opcode();
    uint16_t aa = get_aa();
    uint16_t tc = get_tc();
    uint16_t rd = get_rd();
    uint16_t ra = get_ra();
    uint16_t zero = get_zero();
    uint16_t rcode = get_rcode();
    return fmt::format("[id={:d}, flags=[raw={:#x}, qr={:#x}, opcode={:#x}, aa={:#x}, tc={:#x}, "
                       "rd={:#x}, ra={:#x}, zero={:#x}, rcode={:#x}], qdcount={:d}, ancount={:d}, nscount={:d}, arcount={:d}]",
        id, flags, qr, opcode, aa, tc, rd, ra, zero, rcode, qdcount, ancount, nscount, arcount);
}

std::string dns_header::to_json_string()
{
    uint16_t qr = get_qr();
    uint16_t opcode = get_opcode();
    uint16_t aa = get_aa();
    uint16_t tc = get_tc();
    uint16_t rd = get_rd();
    uint16_t ra = get_ra();
    uint16_t zero = get_zero();
    uint16_t rcode = get_rcode();
    return fmt::format("{{\"id\":{:d}, \"flags\":{{\"raw\":\"{:#x}\", \"qr\":\"{:#x}\", \"opcode\":\"{:#x}\", "
                       "\"aa\":\"{:#x}\", \"tc\":\"{:#x}\", \"rd\":\"{:#x}\", \"ra\":\"{:#x}\", \"zero\":\"{:#x}\", \"rcode\":\"{:#x}\"}}, "
                       "\"qdcount\":{:d}, \"ancount\":{:d}, \"nscount\":{:d}, \"arcount\":{:d}}}",
        id, flags, qr, opcode, aa, tc, rd, ra, zero, rcode, qdcount, ancount, nscount, arcount);
}

struct dns_query {
    std::string name;
    uint16_t qtype;
    uint16_t qclass;
    std::string to_string();
    std::string to_json_string();
};

std::string dns_query::to_string()
{
    return fmt::format("[name={:s}, qtype={:d}, qclass={:d}]", name, qtype, qclass);
}

std::string dns_query::to_json_string()
{
    return fmt::format("{{\"name\":\"{:s}\", \"qtype\":{:d}, \"qclass\":{:d}}}", name, qtype, qclass);
}

struct dns_resource {
    std::string name;
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    std::string rdata;
    std::string to_string();
    std::string to_json_string();
};

std::string dns_resource::to_string()
{
    return fmt::format("[name={:s}, rtype={:d}, rclass={:d}, ttl={:d}, rdlength={:d}, rdata={:s}]",
        name, rtype, rclass, ttl, rdlength, rdata);
}

std::string dns_resource::to_json_string()
{
    return fmt::format("{{\"name\":\"{:s}\", \"rtype\":{:d}, \"rclass\":{:d}, \"ttl\":{:d}, "
                       "\"rdlength\":{:d}, \"rdata\":\"{:s}\"}}",
        name, rtype, rclass, ttl, rdlength, rdata);
}

struct dns_msg {
private:
    typedef std::unordered_map<std::string, uint16_t> str_table;
    static bool is_compress_flag(uint8_t* buf);
    static uint16_t read_compress_flag(uint8_t* buf);
    static size_t write_compress_flag(uint8_t* buf, uint16_t flag);
    static size_t write_raw_str(uint8_t* buf, std::string str);
    static std::string read_ipv4(uint8_t* buf);
    static std::string read_ipv6(uint8_t* buf);
    static std::string read_hex(uint8_t* buf, uint16_t len);
    static std::tuple<std::string, size_t> read_string(uint8_t* buf, size_t offset, str_table& table);
    static size_t write_string(uint8_t* buf, size_t offset, str_table& table, std::string& domain);
    static std::tuple<dns_resource, size_t> read_resource(uint8_t* buf, size_t offset, str_table& table);
    static size_t write_resource(uint8_t* buf, size_t offset, str_table& table, dns_resource& resource);

public:
    dns_header header;
    std::vector<dns_query> query;
    std::vector<dns_resource> answer;
    std::vector<dns_resource> ns;
    std::vector<dns_resource> extra;
    packet_type to_packet();
    static std::unique_ptr<dns_msg> from_packet(packet_type packet);
    static std::unique_ptr<dns_msg> from_domain(const std::string& domain, uint16_t id);
    static std::unique_ptr<dns_msg> from_ipaddr(const std::string& addr, uint16_t id);
    std::string to_string();
    std::string to_json_string();
};

bool dns_msg::is_compress_flag(uint8_t* buf)
{
    return (buf[0] & 0xC0) == 0xC0;
}

uint16_t dns_msg::read_compress_flag(uint8_t* buf)
{
    uint16_t compress_offset = 0;
    compress_offset = ((uint16_t)buf[0] << 8) | (uint16_t)buf[1];
    compress_offset = compress_offset & 0x3FFF;
    return compress_offset;
}

size_t dns_msg::write_compress_flag(uint8_t* buf, uint16_t flag)
{
    flag = flag | 0xC000;
    buf[0] = flag >> 8;
    buf[1] = flag & 0xFF;
    return 2;
}

size_t dns_msg::write_raw_str(uint8_t* buf, std::string str)
{
    uint8_t str_len = str.length();
    size_t offset = 0;
    write_uint8(buf + offset, str_len);
    offset = offset + 1;
    write_bytes(buf + offset, (uint8_t*)str.c_str(), 1, str_len);
    offset = offset + str_len;
    return offset;
}

std::string dns_msg::read_ipv4(uint8_t* buf)
{
    uint8_t addr[4] {};
    read_bytes(buf, addr, 1, 4);
    return fmt::format("{:d}.{:d}.{:d}.{:d}", addr[0], addr[1], addr[2], addr[3]);
}

std::string dns_msg::read_ipv6(uint8_t* buf)
{
    uint16_t addr[8] {};
    for (int i = 0; i != 8; i++) {
        auto offset = 16 - 2 - i * 2;
        addr[i] = read_uint16(buf + offset);
    }
    return fmt::format("{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
}

std::string dns_msg::read_hex(uint8_t* buf, uint16_t len)
{
    std::string str {};
    if (len == 0) {
        return str;
    }
    str.reserve(len * 2 + 2);
    str.append("0x");
    for (uint16_t i = 0; i != len; i++) {
        str.append(fmt::format("{:x}", buf[len]));
    }
    return str;
}

std::tuple<std::string, size_t> dns_msg::read_string(uint8_t* buf, size_t offset, str_table& table)
{
    std::string res {};
    uint8_t* begin = buf + offset;
    size_t now = 0;
    while (true) {
        if (is_compress_flag(begin + now)) {
            //compressed string must be the last part of the string, or the whole part of the string.
            uint16_t lookup_offset = read_compress_flag(begin + now);
            now = now + 2;
            if (res.length() != 0) {
                res.push_back('.');
            }
            res.append(std::get<0>(read_string(buf, lookup_offset, table)));
            break;
        } else {
            uint8_t str_len = read_uint8(begin + now);
            now = now + 1;
            if (str_len == 0) {
                break;
            }
            if (res.length() != 0) {
                res.push_back('.');
            }
            res.append({ (char*)(begin + now), str_len });
            now = now + str_len;
        }
    }
    return { res, now };
}

size_t dns_msg::write_string(uint8_t* buf, size_t offset, str_table& table, std::string& domain)
{
    size_t now = offset;
    if (table.find(domain) == table.end()) {
        table[domain] = (uint16_t)now;
        size_t pos = 0;
        size_t new_pos = 0;
        while (true) {
            new_pos = domain.find_first_of('.', pos);
            std::string str = domain.substr(pos, new_pos - pos);
            if (table.find(str) == table.end()) {
                table[str] = (uint16_t)now;
            }
            now = now + write_raw_str(buf + now, str);
            if (new_pos == std::string::npos) {
                break;
            }
            pos = new_pos + 1;
        }
        write_uint8(buf + now, 0);
        now = now + 1;
    } else {
        uint16_t domain_offset = table[domain];
        now = now + write_compress_flag(buf + now, domain_offset);
    }
    return now - offset;
}

std::tuple<dns_resource, size_t> dns_msg::read_resource(uint8_t* buf, size_t offset, str_table& table)
{
    dns_resource resource {};
    size_t now = offset;
    auto domain = read_string(buf, now, table);
    now = now + std::get<1>(domain);
    resource.name = std::get<0>(domain);
    resource.rtype = read_uint16(buf + now);
    now = now + 2;
    resource.rclass = read_uint16(buf + now);
    now = now + 2;
    resource.ttl = read_uint32(buf + now);
    now = now + 4;
    resource.rdlength = read_uint16(buf + now);
    now = now + 2;
    if (resource.rtype == DNS_IPV4_TYPE) {
        resource.rdata = read_ipv4(buf + now);
    } else if (resource.rtype == DNS_CNAME_TYPE) {
        resource.rdata = std::get<0>(read_string(buf, now, table));
    } else if (resource.rtype == DNS_IPV6_TYPE) {
        resource.rdata = read_ipv6(buf + now);
    } else if (resource.rtype == DNS_PTR_TYPE) {
        resource.rdata = std::get<0>(read_string(buf, now, table));
    } else {
        resource.rdata = read_hex(buf + now, resource.rdlength);
    }
    now = now + resource.rdlength;
    return { resource, now - offset };
}

size_t dns_msg::write_resource(uint8_t* buf, size_t offset, str_table& table, dns_resource& resource)
{
    size_t now = offset;
    now = now + write_string(buf, now, table, resource.name);
    write_uint16(buf + now, resource.rtype);
    now = now + 2;
    write_uint16(buf + now, resource.rclass);
    now = now + 2;
    write_uint32(buf + now, resource.ttl);
    now = now + 4;
    write_uint16(buf + now, resource.rdlength);
    now = now + 2;
    //TODO
    //write rdata(format by the rule according to the rtype)
    now = now + resource.rdlength;
    return now - offset;
}

packet_type dns_msg::to_packet()
{
    str_table table {};
    uint8_t* buf = new uint8_t[512];
    size_t offset = 0;
    //header
    write_uint16(buf + offset, header.id);
    offset = offset + 2;
    write_uint16(buf + offset, header.flags);
    offset = offset + 2;
    write_uint16(buf + offset, header.qdcount);
    offset = offset + 2;
    write_uint16(buf + offset, header.ancount);
    offset = offset + 2;
    write_uint16(buf + offset, header.nscount);
    offset = offset + 2;
    write_uint16(buf + offset, header.arcount);
    offset = offset + 2;
    //query
    for (uint16_t i = 0; i != header.qdcount; i++) {
        auto& q = query[i];
        offset = offset + write_string(buf, offset, table, q.name);
        write_uint16(buf + offset, q.qtype);
        offset = offset + 2;
        write_uint16(buf + offset, q.qclass);
        offset = offset + 2;
    }
    //answer
    for (uint16_t i = 0; i != header.ancount; i++) {
        offset = offset + write_resource(buf, offset, table, answer[i]);
    }
    //ns
    for (uint16_t i = 0; i != header.nscount; i++) {
        offset = offset + write_resource(buf, offset, table, ns[i]);
    }
    //extra
    for (uint16_t i = 0; i != header.arcount; i++) {
        offset = offset + write_resource(buf, offset, table, extra[i]);
    }
    return { std::shared_ptr<uint8_t[]>(buf), offset };
}

std::unique_ptr<dns_msg> dns_msg::from_packet(packet_type packet)
{
    str_table table {};
    std::unique_ptr<dns_msg> msg { new dns_msg() };
    uint8_t* buf = std::get<0>(packet).get();
    size_t offset = 0;
    //header
    msg->header.id = read_uint16(buf + offset);
    offset = offset + 2;
    msg->header.flags = read_uint16(buf + offset);
    offset = offset + 2;
    msg->header.qdcount = read_uint16(buf + offset);
    offset = offset + 2;
    msg->header.ancount = read_uint16(buf + offset);
    offset = offset + 2;
    msg->header.nscount = read_uint16(buf + offset);
    offset = offset + 2;
    msg->header.arcount = read_uint16(buf + offset);
    offset = offset + 2;
    //query
    for (uint16_t i = 0; i != msg->header.qdcount; i++) {
        dns_query query {};
        auto domain = read_string(buf, offset, table);
        offset = offset + std::get<1>(domain);
        query.name = std::get<0>(domain);
        query.qtype = read_uint16(buf + offset);
        offset = offset + 2;
        query.qclass = read_uint16(buf + offset);
        offset = offset + 2;
        msg->query.push_back(query);
    }
    //answer
    for (uint16_t i = 0; i != msg->header.ancount; i++) {
        auto resource = read_resource(buf, offset, table);
        offset = offset + std::get<1>(resource);
        msg->answer.push_back(std::get<0>(resource));
    }
    //ns
    for (uint16_t i = 0; i != msg->header.nscount; i++) {
        auto resource = read_resource(buf, offset, table);
        offset = offset + std::get<1>(resource);
        msg->ns.push_back(std::get<0>(resource));
    }
    //extra
    for (uint16_t i = 0; i != msg->header.arcount; i++) {
        auto resource = read_resource(buf, offset, table);
        offset = offset + std::get<1>(resource);
        msg->extra.push_back(std::get<0>(resource));
    }
    return msg;
}

std::unique_ptr<dns_msg> dns_msg::from_domain(const std::string& domain, uint16_t id)
{
    std::unique_ptr<dns_msg> msg { new dns_msg() };
    msg->header.id = id;
    msg->header.qdcount = 1;
    dns_query query {};
    query.name = domain;
    query.qtype = 1;
    query.qclass = 1;
    msg->query.push_back(query);
    return msg;
}

//about the ipv4 address, you can see:https://tools.ietf.org/html/rfc1035 (in the 3.3.12. PTR RDATA format)
//about the ipv6 address, you can see:https://tools.ietf.org/html/rfc8501
std::unique_ptr<dns_msg> dns_msg::from_ipaddr(const std::string& addr, uint16_t id)
{
    std::unique_ptr<dns_msg> msg { new dns_msg() };
    msg->header.id = id;
    msg->header.qdcount = 1;
    dns_query query {};
    query.name = addr;
    query.qtype = 12; //PTR
    query.qclass = 1;
    msg->query.push_back(query);
    return msg;
}

std::string dns_msg::to_string()
{
    if (header.get_rcode() == 1) {
        return "Format error - The name server was unable to interpret the query.";
    } else if (header.get_rcode() == 2) {
        return "Server failure - The name server was unable to process this query "
               "due to a problem with the name server.";
    } else if (header.get_rcode() == 3) {
        return "Name Error - Meaningful only for responses from an authoritative name server, "
               "this code signifies that the domain name referenced in the query does not exist.";
    } else if (header.get_rcode() == 4) {
        return "Not Implemented - The name server does not support the requested kind of query.";
    } else if (header.get_rcode() == 5) {
        return "Refused - The name server refuses to perform the specified operation for policy reasons. "
               "For example, a name server may not wish to provide the information to the particular requester, "
               "or a name server may not wish to perform a particular operation";
    }
    std::string query_str { "[" };
    for (size_t i = 0; i != query.size(); i++) {
        query_str.append(query[i].to_string());
        if (i != query.size() - 1) {
            query_str.append(", ");
        }
    }
    query_str.append("]");
    std::string ans_str { "[" };
    for (size_t i = 0; i != answer.size(); i++) {
        ans_str.append(answer[i].to_string());
        if (i != answer.size() - 1) {
            ans_str.append(", ");
        }
    }
    ans_str.append("]");
    std::string ns_str { "[" };
    for (size_t i = 0; i != ns.size(); i++) {
        ns_str.append(ns[i].to_string());
        if (i != ns.size() - 1) {
            ns_str.append(", ");
        }
    }
    ns_str.append("]");
    std::string ext_str { "[" };
    for (size_t i = 0; i != extra.size(); i++) {
        ext_str.append(extra[i].to_string());
        if (i != extra.size() - 1) {
            ext_str.append(", ");
        }
    }
    ext_str.append("]");
    return fmt::format("[header={:s}, query={:s}, answer={:s}, ns={:s}, extra={:s}]",
        header.to_string(), query_str, ans_str, ns_str, ext_str);
}

std::string dns_msg::to_json_string()
{
    if (header.get_rcode() == 1) {
        return "Format error - The name server was unable to interpret the query.";
    } else if (header.get_rcode() == 2) {
        return "Server failure - The name server was unable to process this query "
               "due to a problem with the name server.";
    } else if (header.get_rcode() == 3) {
        return "Name Error - Meaningful only for responses from an authoritative name server, "
               "this code signifies that the domain name referenced in the query does not exist.";
    } else if (header.get_rcode() == 4) {
        return "Not Implemented - The name server does not support the requested kind of query.";
    } else if (header.get_rcode() == 5) {
        return "Refused - The name server refuses to perform the specified operation for policy reasons. "
               "For example, a name server may not wish to provide the information to the particular requester, "
               "or a name server may not wish to perform a particular operation";
    }
    std::string query_str { "[" };
    for (size_t i = 0; i != query.size(); i++) {
        query_str.append(query[i].to_json_string());
        if (i != query.size() - 1) {
            query_str.append(", ");
        }
    }
    query_str.append("]");
    std::string ans_str { "[" };
    for (size_t i = 0; i != answer.size(); i++) {
        ans_str.append(answer[i].to_json_string());
        if (i != answer.size() - 1) {
            ans_str.append(", ");
        }
    }
    ans_str.append("]");
    std::string ns_str { "[" };
    for (size_t i = 0; i != ns.size(); i++) {
        ns_str.append(ns[i].to_json_string());
        if (i != ns.size() - 1) {
            ns_str.append(", ");
        }
    }
    ns_str.append("]");
    std::string ext_str { "[" };
    for (size_t i = 0; i != extra.size(); i++) {
        ext_str.append(extra[i].to_json_string());
        if (i != extra.size() - 1) {
            ext_str.append(", ");
        }
    }
    ext_str.append("]");
    return fmt::format("{{\"header\":{:s}, \"query\":{:s}, \"answer\":{:s}, \"ns\":{:s}, \"extra\":{:s}}}",
        header.to_json_string(), query_str, ans_str, ns_str, ext_str);
}

}

#endif