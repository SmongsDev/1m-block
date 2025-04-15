#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <cstring>
#include <string>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iostream>

using namespace std;

// 전역 변수로 unordered_set 선언
unordered_set<string> blocked_hosts;

// IP 헤더 구조체
struct ip_header {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

// TCP 헤더 구조체
struct tcp_header {
    u_short th_sport;
    u_short th_dport;
    u_int th_seq;
    u_int th_ack;
    u_char th_offx2;
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

void dump(unsigned char* buf, int size) {
    for (int i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

// 호스트 차단 여부 확인 함수
static int check_http_host(unsigned char* data, int size) {
    string http_data(reinterpret_cast<char*>(data), size);
    size_t host_pos = http_data.find("Host: ");
    
    if (host_pos != string::npos) {
        size_t host_end = http_data.find("\r\n", host_pos);
        if (host_end != string::npos) {
            string host = http_data.substr(host_pos + 6, host_end - (host_pos + 6));
            
            cout << "Found Host: " << host << endl;

            auto start = chrono::high_resolution_clock::now();
            bool is_blocked = (blocked_hosts.find(host) != blocked_hosts.end());
            auto end = chrono::high_resolution_clock::now();
            
            chrono::duration<double> search_time = end - start;
            cout << "Search time: " << search_time.count() << " seconds" << endl;

            if (is_blocked) {
                cout << "Matched blocked host! Dropping packet." << endl;
                return 1;
            }
        }
    }
    return 0;
}

static u_int32_t print_pkt(struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        struct ip_header *iph = (struct ip_header *)data;
        int ip_header_len = (iph->ip_vhl & 0x0f) * 4;

        if (iph->ip_p == 6) {  // TCP
            struct tcp_header *tcph = (struct tcp_header *)(data + ip_header_len);
            int tcp_header_len = ((tcph->th_offx2 & 0xf0) >> 4) * 4;

            if (ntohs(tcph->th_dport) == 80) {
                unsigned char *http_data = data + ip_header_len + tcp_header_len;
                int http_length = ret - ip_header_len - tcp_header_len;

                if (http_length > 0 && 
                    (strncmp((char*)http_data, "GET ", 4) == 0 ||
                     strncmp((char*)http_data, "POST ", 5) == 0)) {
                    check_http_host(http_data, http_length);
                }
            }
        }
    }

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
             struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);
    int blocked = 0;

    unsigned char *payload_data;
    int payload_len = nfq_get_payload(nfa, &payload_data);
    
    if (payload_len >= 0) {
        struct ip_header *iph = (struct ip_header *)payload_data;
        if (iph->ip_p == 6) {
            int ip_header_len = (iph->ip_vhl & 0x0f) * 4;
            struct tcp_header *tcph = (struct tcp_header *)(payload_data + ip_header_len);
            
            if (ntohs(tcph->th_dport) == 80) {
                int tcp_header_len = ((tcph->th_offx2 & 0xf0) >> 4) * 4;
                unsigned char *http_data = payload_data + ip_header_len + tcp_header_len;
                int http_length = payload_len - ip_header_len - tcp_header_len;
                blocked = check_http_host(http_data, http_length);
            }
        }
    }

    return nfq_set_verdict(qh, id, blocked ? NF_DROP : NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <site_list_file>" << endl;
        exit(1);
    }

    // 사이트 리스트 로딩
    auto start = chrono::high_resolution_clock::now();

	ifstream file(argv[1]);
	string host;
	while (getline(file, host)) {
		// 줄 끝의 공백 문자 제거
		host.erase(0, host.find_first_not_of(" \t\r\n"));
		host.erase(host.find_last_not_of(" \t\r\n") + 1);
		
		if (!host.empty()) {  // 빈 줄 무시
			blocked_hosts.insert(host);
		}
	}

auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> load_time = end - start;
    
    cout << "Loaded " << blocked_hosts.size() << " sites in "
         << load_time.count() << " seconds" << endl;

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    cout << "Opening library handle" << endl;
    h = nfq_open();
    if (!h) {
        cerr << "Error during nfq_open()" << endl;
        exit(1);
    }

    cout << "Unbinding existing nf_queue handler for AF_INET" << endl;
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        cerr << "Error during nfq_unbind_pf()" << endl;
        exit(1);
    }

    cout << "Binding nfnetlink_queue as nf_queue handler for AF_INET" << endl;
    if (nfq_bind_pf(h, AF_INET) < 0) {
        cerr << "Error during nfq_bind_pf()" << endl;
        exit(1);
    }

    cout << "Binding this socket to queue '0'" << endl;
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        cerr << "Error during nfq_create_queue()" << endl;
        exit(1);
    }

    cout << "Setting copy_packet mode" << endl;
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        cerr << "Can't set packet_copy mode" << endl;
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        cout << "Packet received" << endl;
        nfq_handle_packet(h, buf, rv);
    }

    cout << "Unbinding from queue 0" << endl;
    nfq_destroy_queue(qh);
    cout << "Closing library handle" << endl;
    nfq_close(h);

    return 0;
}