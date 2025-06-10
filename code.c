#include <epan/packet.h>

static int proto_ddos_guard = -1;
static int hf_ddos_guard_tcp_flood_count = -1;
static int hf_ddos_guard_udp_flood_count = -1;
static int hf_ddos_guard_syn_flood_count = -1;

static guint32 tcp_flood_counter = 0;
static guint32 udp_flood_counter = 0;
static guint32 syn_flood_counter = 0;

// Thresholds for flood detection
static const guint32 TCP_FLOOD_THRESHOLD = 1000;
static const guint32 UDP_FLOOD_THRESHOLD = 1000;
static const guint32 SYN_FLOOD_THRESHOLD = 1000;

static int ddos_guard_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    // Check if the packet is TCP
    if (pinfo->ptype == PT_TCP) {
        tcp_flood_counter++;
        // Check for SYN flag (TCP header flags are in the 13th byte)
        if (tvb_get_guint8(tvb, 13) & 0x02) { // SYN flag is set
            syn_flood_counter++;
        }
    }

    // Check if the packet is UDP
    if (pinfo->ptype == PT_UDP) {
        udp_flood_counter++;
    }

    // Add to the protocol tree
    if (tree) {
        proto_tree_add_item(tree, hf_ddos_guard_tcp_flood_count, tvb, 0, 0, ENC_NA);
        proto_tree_add_item(tree, hf_ddos_guard_udp_flood_count, tvb, 0, 0, ENC_NA);
        proto_tree_add_item(tree, hf_ddos_guard_syn_flood_count, tvb, 0, 0, ENC_NA);
    }

    // Print messages if flood thresholds are reached
    if (tcp_flood_counter > TCP_FLOOD_THRESHOLD) {
        printf("DDoSGuard: Potential TCP flood detected: %u packets\n", tcp_flood_counter);
    }
    if (udp_flood_counter > UDP_FLOOD_THRESHOLD) {
        printf("DDoSGuard: Potential UDP flood detected: %u packets\n", udp_flood_counter);
    }
    if (syn_flood_counter > SYN_FLOOD_THRESHOLD) {
        printf("DDoSGuard: Potential SYN flood detected: %u packets\n", syn_flood_counter);
    }

    return tvb_captured_length(tvb);
}

void proto_register_ddos_guard(void) {
    static hf_register_info hf[] = {
        { &hf_ddos_guard_tcp_flood_count,
          { "TCP Flood Count", "ddos_guard.tcp_flood_count",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            "Count of TCP packets", HFILL }
        },
        { &hf_ddos_guard_udp_flood_count,
          { "UDP Flood Count", "ddos_guard.udp_flood_count",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            "Count of UDP packets", HFILL }
        },
        { &hf_ddos_guard_syn_flood_count,
          { "SYN Flood Count", "ddos_guard.syn_flood_count",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            "Count of SYN packets", HFILL }
        },
    };

    proto_ddos_guard = proto_register_protocol("DDoSGuard", "DDoSGuard", "ddos_guard");
    proto_register_field_array(proto_ddos_guard, hf, array_length(hf));
}

void proto_reg_handoff_ddos_guard(void) {
    static dissector_handle_t ddos_guard_handle;

    ddos_guard_handle = create_dissector_handle(ddos_guard_dissector, proto_ddos_guard);
    dissector_add("tcp", 0, ddos_guard_handle);
    dissector_add("udp", 0, ddos_guard_handle);
}
