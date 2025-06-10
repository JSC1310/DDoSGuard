# DDoSGuard
Wireshark Plugin for TCP, UDP and SYN Flood Attacks

*  DDoSGuard Wireshark Dissector  *

This project provides a simple custom Wireshark dissector written in C that identifies and flags suspicious traffic, such as potential Distributed Denial of Service (DDoS) activity, on a specific UDP port (default: **9999**).

*  Features  *

- Registers a custom protocol: `DDoSGuard`
- Detects and marks traffic on UDP port `9999`
- Displays a custom message in the packet details pane
- Adds protocol information to the Wireshark UI (Protocol & Info columns)

*  Build Instructions  *

*  Prerequisites  *

To compile and use this dissector, you need:

- A working Wireshark source tree
- Development tools: GCC, CMake, or Autotools (depends on your platform)
- Familiarity with building Wireshark plugins

*  Building as a Plugin  *

1. Clone the Wireshark source (or use your existing one):

    ```bash
    git clone https://gitlab.com/wireshark/wireshark.git
    cd wireshark
    ```

2. Copy your dissector files into the `plugins/` directory:

    ```bash
    mkdir plugins/ddosguard
    cp /path/to/ddosguard.c plugins/ddosguard/
    ```

3. Create a `CMakeLists.txt` file inside `plugins/ddosguard/`:

    ```cmake
    add_plugin_library(ddosguard
        ddosguard.c
    )
    ```

4. From the root of the Wireshark source:

    ```bash
    mkdir build && cd build
    cmake ..
    make
    ```

> Note: Ensure you have installed all dependencies as listed in the Wireshark developer guide.

*  Usage  *

Once compiled and loaded into Wireshark:

1. Open a pcap file or live capture with traffic on UDP port **9999**.
2. Wireshark will dissect it using the `DDoSGuard` protocol.
3. You’ll see a message: **"Suspicious traffic detected"** in the packet details pane.
