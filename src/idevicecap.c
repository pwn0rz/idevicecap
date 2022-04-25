#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/property_list_service.h>
#include <plist/plist.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>

#pragma pack(push)
#pragma pack(1)

typedef struct iptap_hdr_t
{
    uint32_t hdr_length;
    uint8_t version;
    uint32_t length;
    uint8_t type;
    uint16_t unit;
    uint8_t io;
    uint32_t protocol_family;
    uint32_t frame_pre_length;
    uint32_t frame_pst_length;
    char if_name[16];
    uint32_t pid;
    char comm[17];
    uint32_t svc;
    uint32_t epid;
    char ecomm[17];
    struct timeval ts;
} iptap_hdr_t;

#pragma pack(pop)

// refer bsd/net/pktap.h

void usage()
{
    fprintf(stderr,
            "Usage: idevicecap\n"
            "\n"
            "\t-s UDID\n"
            "\t-o OUTPUT [optional] write to file, stdout if not set\n"
            "\t-n PROCNAME [optional] process name filter\n"
            "\t-q disable log");
}

atomic_bool should_shutdown = false;

void sigint_handler()
{
    fprintf(stderr, "shutting down...");
    atomic_store(&should_shutdown, true);
}

void hexdump(const void *data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i)
    {
        fprintf(stderr, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~')
        {
            ascii[i % 16] = ((unsigned char *)data)[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            fprintf(stderr, " ");
            if ((i + 1) % 16 == 0)
            {
                fprintf(stderr, "|  %s \n", ascii);
            }
            else if (i + 1 == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8)
                {
                    fprintf(stderr, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j)
                {
                    fprintf(stderr, "   ");
                }
                fprintf(stderr, "|  %s \n", ascii);
            }
        }
    }
}

int main(int argc, char *argv[])
{
    const char *udid = NULL;
    const char *output_file = NULL;
    const char *procname = NULL;
    bool verbose = true;

    idevice_t dev = NULL;
    lockdownd_client_t lockdown = NULL;
    lockdownd_service_descriptor_t pcapd_service = NULL;

    int ch = 0;
    while ((ch = getopt(argc, argv, "s:o:n:q")) != -1)
    {
        switch (ch)
        {
        case 's':
            udid = optarg;
            break;
        case 'o':
            output_file = optarg;
            break;
        case 'n':
            procname = optarg;
            break;
        case 'q':
            verbose = false;
            break;
        case '?':
        case 'h':
        default:
            usage();
            return 1;
        }
    }
    argc += optind;
    argv += optind;
    if (udid == NULL)
    {

        int32_t dev_count = 0;
        int usb_dev_count = 0;
        while (usb_dev_count == 0 || udid == NULL)
        {
            idevice_info_t *devices = NULL;
            assert(IDEVICE_E_SUCCESS == idevice_get_device_list_extended(&devices, &dev_count));

            int last_usb_dev_id = -1;
            
            usb_dev_count = 0;
            for(int32_t i=0;i<dev_count;i++){
                if (devices[i]->conn_type == CONNECTION_USBMUXD)
                {
                    last_usb_dev_id =  i;
                    usb_dev_count += 1;
                }
            }
            
            if(usb_dev_count == 0){
                fprintf(stderr, "\r[*] wating for usb device...");
                fflush(stderr);
                sleep(1);
            }else if(usb_dev_count > 1){
                fprintf(stderr, "\r[!] more than one USB device, you have to specify device ID\n");
                for (int32_t i = 0; i < dev_count; i++)
                {
                    if (devices[0]->conn_type == CONNECTION_USBMUXD){
                        fprintf(stderr, "%s\n", devices[i]->udid);
                    }   
                }
            }else{
                udid = strdup(devices[last_usb_dev_id]->udid);
            }
            
            if (devices != NULL)
            {
                idevice_device_list_extended_free(devices);
            }
            if (usb_dev_count > 1)
            {
                abort();
            }
        }
    }

    fprintf(stderr, "\r[*] selecting device %s\n", udid);

    assert(IDEVICE_E_SUCCESS == idevice_new_with_options(&dev, udid, IDEVICE_LOOKUP_USBMUX));
    assert(LOCKDOWN_E_SUCCESS == lockdownd_client_new_with_handshake(dev, &lockdown, "idevicecap"));
    assert(LOCKDOWN_E_SUCCESS == lockdownd_start_service(lockdown, "com.apple.pcapd", &pcapd_service));
    assert(pcapd_service && pcapd_service->port);

    lockdownd_client_free(lockdown);

    property_list_service_client_t pcapd_client = NULL;
    assert(PROPERTY_LIST_SERVICE_E_SUCCESS ==
           property_list_service_client_new(dev, pcapd_service, &pcapd_client));

    lockdownd_service_descriptor_free(pcapd_service);

    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
    pcap_dumper_t *dumper = NULL;
    if (output_file)
    {
        dumper = pcap_dump_open(pcap, output_file);
    }
    else
    {
        dumper = pcap_dump_fopen(pcap, stdout);
    }
    assert(pcap != NULL);
    assert(dumper != NULL);

    signal(SIGINT, sigint_handler);

    // read plist from lockdownd port again and again
    while (true)
    {
        plist_t plist = NULL;

        if (atomic_load(&should_shutdown))
        {
            break;
        }
        property_list_service_error_t pe = property_list_service_receive_plist_with_timeout(pcapd_client, &plist, 100);
        if (pe == PROPERTY_LIST_SERVICE_E_RECEIVE_TIMEOUT)
        {
            continue;
        }
        assert(PROPERTY_LIST_SERVICE_E_SUCCESS == pe);

        char *data = NULL;
        uint64_t data_len = 0;
        plist_get_data_val(plist, &data, &data_len);
        assert(data != NULL && data_len != 0);

        struct iptap_hdr_t *tap_hdr = (struct iptap_hdr_t *)data;
        tap_hdr->hdr_length = ntohl(tap_hdr->hdr_length);
        tap_hdr->length = ntohl(tap_hdr->length);
        tap_hdr->protocol_family = ntohl(tap_hdr->protocol_family);
        tap_hdr->ts.tv_sec = ntohl(tap_hdr->ts.tv_sec);
        tap_hdr->ts.tv_usec = ntohl(tap_hdr->ts.tv_usec);

        if (procname != NULL && strncmp(tap_hdr->comm, procname, 16) != 0 && strncmp(tap_hdr->ecomm, procname, 16) != 0)
        {
            continue;
        }

        // verbose && fprintf(stderr, "Header (%d bytes):\n", tap_hdr->hdr_length);
        //  assert will fail if on VPN
        if (!(tap_hdr->type == 0x06 /*Ethernet*/ || tap_hdr->type == 0xff /*celluar*/))
        {
            fprintf(stderr, "unknown iptap type: %#x\n", tap_hdr->type);
            continue;
        }
        assert(tap_hdr->type == 0x06 /*Ethernet*/ || tap_hdr->type == 0xff /*celluar*/);

        verbose &&fprintf(stderr, "iface: %s, type=%s, proto_family=%d, process: %s, pid: %d, eprocess: %s, epid: %d, header: %d bytes, body: %d bytes\n",
                          tap_hdr->if_name,
                          tap_hdr->type == 0x06 ? "ethernet" : "celluar", // TODO
                          tap_hdr->protocol_family,
                          tap_hdr->comm[0] == '\x00' ? "N/A" : tap_hdr->comm,
                          tap_hdr->pid,
                          tap_hdr->ecomm[0] == '\x00' ? "N/A" : tap_hdr->ecomm,
                          tap_hdr->epid,
                          tap_hdr->hdr_length,
                          tap_hdr->length);

        // verbose && hexdump(data, tap_hdr->hdr_length);
        // if(tap_hdr->length < 1024){
        //     verbose && fprintf(stderr, "Body:\n");
        //     verbose && hexdump(data + tap_hdr->hdr_length, tap_hdr->length);
        // }

        struct pcap_pkthdr pcap_hdr;
        pcap_hdr.ts.tv_sec = tap_hdr->ts.tv_sec;
        pcap_hdr.ts.tv_usec = tap_hdr->ts.tv_usec;

        ether_header_t *eth_hdr = NULL;
        if (tap_hdr->type == 0x06 /*Ethernet*/)
        {
            pcap_hdr.caplen = tap_hdr->length;
            pcap_hdr.len = tap_hdr->length;
            pcap_dump((u_char *)dumper, &pcap_hdr, (u_char *)(data + tap_hdr->hdr_length));
        }
        else if (tap_hdr->type == 0xff /*celluar*/)
        {
            uint32_t pkt_size = sizeof(ether_header_t) + tap_hdr->length - 4;
            eth_hdr = (ether_header_t *)malloc(pkt_size);
            memset(eth_hdr->ether_dhost, 0, 6);
            memset(eth_hdr->ether_shost, 0, 6);

            assert(tap_hdr->protocol_family == PF_INET || tap_hdr->protocol_family == PF_INET6);
            if (tap_hdr->protocol_family == PF_INET)
            {
                eth_hdr->ether_type = htons(ETHERTYPE_IP);
            }
            else if (tap_hdr->protocol_family == PF_INET6)
            {
                eth_hdr->ether_type = htons(ETHERTYPE_IPV6);
            }
            memcpy((void *)((uintptr_t)eth_hdr + sizeof(ether_header_t)), data + tap_hdr->hdr_length + 4, pkt_size - sizeof(ether_header_t));

            pcap_hdr.caplen = pkt_size;
            pcap_hdr.len = pkt_size;
            pcap_dump((u_char *)dumper, &pcap_hdr, (u_char *)eth_hdr);
        }

        if (eth_hdr)
        {
            free(eth_hdr);
            eth_hdr = NULL;
        }
        pcap_dump_flush(dumper);
        free(data);
    }
    pcap_dump_close(dumper);
    pcap_close(pcap);
}