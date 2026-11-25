# SDEx vs WireGuard vs OpenVPN — same lab, same procedure

Source: `bench/cmp_{baseline,sdex,wireguard,openvpn}.jsonl`; first 3 iterations of each series discarded as warm-up.

## Configurations compared

| tunnel | inner subnet | device | transport | cipher | parallelism |
|---|---|---|---|---|---|
| sdex | 10.0.0.0/24 | tun0 | UDP/51820 | SDEx (BLAKE3-based) | 4 workers |
| wireguard | 10.66.0.0/24 | sdexbench | UDP/51821 | ChaCha20-Poly1305 | kernel, multicore path |
| openvpn | 10.67.0.0/24 | tun10 | UDP/1195 | AES-256-GCM (TLS 1.3 control channel) | single process |

## Baseline (no tunnel)

| path | scenario | n | mean Mbps | stdev | 95% CI |
|---|---|---|---|---|---|
| baseline_a | tcp1 | 7 | 15372.24 | 550.38 | 14964.51–15779.97 |
| baseline_a | tcp4 | 7 | 18858.39 | 4803.71 | 15299.75–22417.03 |
| baseline_a | tcp1_mss | 7 | 14748.28 | 640.45 | 14273.82–15222.73 |
| baseline_a | udp64 | 7 | 99.90 | 0.08 | 99.84–99.97 |
| baseline_a | udp512 | 7 | 499.89 | 0.05 | 499.85–499.93 |
| baseline_a | udp1200 | 7 | 999.50 | 0.43 | 999.18–999.81 |
| baseline_a | udp1472 | 7 | 999.65 | 0.10 | 999.58–999.73 |
| baseline_b | tcp1 | 7 | 31032.97 | 3022.69 | 28793.73–33272.20 |
| baseline_b | tcp4 | 7 | 36196.91 | 2469.22 | 34367.68–38026.13 |
| baseline_b | tcp1_mss | 7 | 31121.45 | 3858.49 | 28263.04–33979.86 |
| baseline_b | udp64 | 7 | 99.91 | 0.05 | 99.87–99.95 |
| baseline_b | udp512 | 7 | 499.87 | 0.06 | 499.83–499.91 |
| baseline_b | udp1200 | 7 | 999.68 | 0.24 | 999.51–999.86 |
| baseline_b | udp1472 | 7 | 999.73 | 0.12 | 999.64–999.82 |

## Through the tunnel (Mbps)

| scenario | SDEx | WireGuard | OpenVPN | best |
|---|---|---|---|---|
| tcp1 | 1093.74 | 4133.49 | 785.82 | wireguard |
| tcp4 | 1149.11 | 4123.43 | 789.34 | wireguard |
| tcp1_mss | 1258.74 | 4097.44 | 764.99 | wireguard |
| udp64 | 86.10 | 99.77 | 56.50 | wireguard |
| udp512 | 499.77 | 499.88 | 430.60 | wireguard |
| udp1200 | 999.22 | 999.78 | 913.51 | wireguard |
| udp1472 | 999.16 | 999.46 | 997.12 | wireguard |

## Full statistics per tunnel

| tunnel | scenario | n | mean | median | stdev | min | max | 95% CI | client CPU % | server CPU % | loss % | retrans |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| sdex | tcp1 | 27 | 1093.74 | 1090.62 | 37.75 | 1036.25 | 1169.99 | 1079.50–1107.98 | 88.0 | 129.3 | — | 183 |
| sdex | tcp4 | 27 | 1149.11 | 1150.37 | 46.22 | 1020.44 | 1229.27 | 1131.67–1166.54 | 100.3 | 127.8 | — | 1085 |
| sdex | tcp1_mss | 27 | 1258.74 | 1244.77 | 62.65 | 1113.34 | 1365.40 | 1235.11–1282.37 | 92.8 | 140.6 | — | 176 |
| sdex | udp64 | 27 | 86.10 | 87.67 | 9.04 | 65.71 | 99.89 | 82.69–89.51 | 94.2 | 147.3 | 13.0 | — |
| sdex | udp512 | 27 | 499.77 | 499.89 | 0.32 | 498.34 | 499.94 | 499.65–499.89 | 76.1 | 114.5 | 0.0 | — |
| sdex | udp1200 | 27 | 999.22 | 999.72 | 2.35 | 987.51 | 999.85 | 998.33–1000.10 | 86.4 | 126.3 | 0.1 | — |
| sdex | udp1472 | 27 | 999.16 | 999.74 | 2.54 | 986.55 | 999.88 | 998.20–1000.11 | 85.6 | 124.6 | 0.1 | — |
| wireguard | tcp1 | 27 | 4133.49 | 4144.63 | 99.02 | 3912.56 | 4308.09 | 4096.14–4170.84 | (148 sys) | — | — | 292 |
| wireguard | tcp4 | 27 | 4123.43 | 4155.78 | 86.43 | 3907.32 | 4232.57 | 4090.83–4156.03 | (152 sys) | — | — | 1248 |
| wireguard | tcp1_mss | 27 | 4097.44 | 4121.52 | 126.75 | 3825.56 | 4393.20 | 4049.63–4145.25 | (147 sys) | — | — | 269 |
| wireguard | udp64 | 27 | 99.77 | 99.80 | 0.13 | 99.44 | 99.95 | 99.72–99.82 | (159 sys) | — | 0.2 | — |
| wireguard | udp512 | 27 | 499.88 | 499.93 | 0.12 | 499.43 | 499.95 | 499.83–499.92 | (131 sys) | — | 0.0 | — |
| wireguard | udp1200 | 27 | 999.78 | 999.85 | 0.24 | 998.62 | 999.90 | 999.69–999.87 | (124 sys) | — | 0.0 | — |
| wireguard | udp1472 | 27 | 999.46 | 999.58 | 0.36 | 998.46 | 999.84 | 999.32–999.60 | (139 sys) | — | 0.0 | — |
| openvpn | tcp1 | 27 | 785.82 | 785.33 | 24.01 | 723.17 | 842.04 | 776.76–794.88 | 70.3 | 73.2 | — | 808 |
| openvpn | tcp4 | 27 | 789.34 | 789.01 | 27.48 | 714.82 | 836.36 | 778.98–799.71 | 74.2 | 75.0 | — | 4628 |
| openvpn | tcp1_mss | 27 | 764.99 | 762.39 | 24.26 | 693.04 | 817.74 | 755.84–774.14 | 70.1 | 73.3 | — | 757 |
| openvpn | udp64 | 27 | 56.50 | 56.96 | 2.71 | 50.74 | 63.24 | 55.48–57.52 | 98.0 | 96.3 | 42.9 | — |
| openvpn | udp512 | 27 | 430.60 | 432.41 | 16.39 | 388.09 | 469.87 | 424.42–436.79 | 97.3 | 96.1 | 13.6 | — |
| openvpn | udp1200 | 27 | 913.51 | 917.87 | 28.28 | 848.42 | 958.04 | 902.84–924.17 | 94.1 | 94.0 | 8.3 | — |
| openvpn | udp1472 | 27 | 997.12 | 997.40 | 1.99 | 989.83 | 999.53 | 996.37–997.87 | 85.6 | 74.7 | 0.3 | — |

## Relative to the no-tunnel path

| scenario | baseline | SDEx | WireGuard | OpenVPN |
|---|---|---|---|---|
| tcp1 | 15372.24 | 7.12% | 26.89% | 5.11% |
| tcp4 | 18858.39 | 6.09% | 21.87% | 4.19% |
| tcp1_mss | 14748.28 | 8.53% | 27.78% | 5.19% |
| udp64 | 99.90 | 86.18% | 99.86% | 56.55% |
| udp512 | 499.89 | 99.98% | 100.00% | 86.14% |
| udp1200 | 999.50 | 99.97% | 100.03% | 91.40% |
| udp1472 | 999.65 | 99.95% | 99.98% | 99.75% |

## Pairwise Mann-Whitney U (two-sided)

| scenario | pair | U | p | significant at 0.05 |
|---|---|---|---|---|
| tcp1 | sdex vs wireguard | 0.0 | 0.0000 | yes |
| tcp1 | sdex vs openvpn | 729.0 | 0.0000 | yes |
| tcp1 | wireguard vs openvpn | 729.0 | 0.0000 | yes |
| tcp4 | sdex vs wireguard | 0.0 | 0.0000 | yes |
| tcp4 | sdex vs openvpn | 729.0 | 0.0000 | yes |
| tcp4 | wireguard vs openvpn | 729.0 | 0.0000 | yes |
| tcp1_mss | sdex vs wireguard | 0.0 | 0.0000 | yes |
| tcp1_mss | sdex vs openvpn | 729.0 | 0.0000 | yes |
| tcp1_mss | wireguard vs openvpn | 729.0 | 0.0000 | yes |
| udp64 | sdex vs wireguard | 22.0 | 0.0000 | yes |
| udp64 | sdex vs openvpn | 729.0 | 0.0000 | yes |
| udp64 | wireguard vs openvpn | 729.0 | 0.0000 | yes |
| udp512 | sdex vs wireguard | 238.0 | 0.0286 | yes |
| udp512 | sdex vs openvpn | 729.0 | 0.0000 | yes |
| udp512 | wireguard vs openvpn | 729.0 | 0.0000 | yes |
| udp1200 | sdex vs wireguard | 122.0 | 0.0000 | yes |
| udp1200 | sdex vs openvpn | 729.0 | 0.0000 | yes |
| udp1200 | wireguard vs openvpn | 729.0 | 0.0000 | yes |
| udp1472 | sdex vs wireguard | 483.0 | 0.0404 | yes |
| udp1472 | sdex vs openvpn | 687.0 | 0.0000 | yes |
| udp1472 | wireguard vs openvpn | 693.0 | 0.0000 | yes |

## Latency (ping, idle tunnel)

| tunnel | packets | summary |
|---|---|---|
| sdex | 100 | 100 packets transmitted, 100 received, 0% packet loss, time 2095ms / rtt min/avg/max/mdev = 0.693/1.076/1.664/0.197 ms |
| wireguard | 100 | 100 packets transmitted, 100 received, 0% packet loss, time 2288ms / rtt min/avg/max/mdev = 0.447/0.777/1.712/0.262 ms |
| openvpn | 100 | 100 packets transmitted, 100 received, 0% packet loss, time 2248ms / rtt min/avg/max/mdev = 0.553/0.889/1.925/0.233 ms |

## Supplementary UDP ceiling probe (offers above 1 Gbps)

| tunnel | scenario | n | mean Mbps | loss % |
|---|---|---|---|---|
| wireguard | udp1200_2G | 3 | 1955.4 | 0.2 |
| wireguard | udp1200_4G | 3 | 1940.0 | 0.2 |
| wireguard | udp1472_2G | 3 | 1193.2 | 22.1 |
| wireguard | udp1472_4G | 3 | 1249.1 | 14.9 |
| openvpn | udp1200_2G | 3 | 1120.5 | 42.4 |
| openvpn | udp1200_4G | 3 | 1089.4 | 72.4 |
| openvpn | udp1472_2G | 3 | 1349.7 | 32.5 |
| openvpn | udp1472_4G | 3 | 1276.4 | 67.6 |
