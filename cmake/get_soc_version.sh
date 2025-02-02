   #!/bin/bash
   awk '/Revision/ { rev = "0x" substr($3, length($3)-3, 4); printf "%d\n", (rev / 4096) % 16 }' /proc/cpuinfo
