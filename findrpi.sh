#!/usr/bin/env bash
set -euo pipefail

# Finds Raspberry Pi devices on locally connected IPv4 subnets.
# Optional usage:
#   ./find_rpis.sh                  # auto-detect local subnets
#   ./find_rpis.sh 192.168.1.0/24   # scan specific subnet

NMAP_MAC_PREFIXES="/usr/share/nmap/nmap-mac-prefixes"

hex_to_ip() {
  local hex="$1"
  printf "%d.%d.%d.%d" \
    "$((16#${hex:6:2}))" \
    "$((16#${hex:4:2}))" \
    "$((16#${hex:2:2}))" \
    "$((16#${hex:0:2}))"
}

mask_to_cidr() {
  local mask_ip="$1"
  local cidr=0
  local octet
  IFS='.' read -r -a octets <<<"$mask_ip"
  for octet in "${octets[@]}"; do
    case "$octet" in
      255) ((cidr+=8)) ;;
      254) ((cidr+=7)) ;;
      252) ((cidr+=6)) ;;
      248) ((cidr+=5)) ;;
      240) ((cidr+=4)) ;;
      224) ((cidr+=3)) ;;
      192) ((cidr+=2)) ;;
      128) ((cidr+=1)) ;;
      0) ;;
      *) echo "Unsupported netmask octet: $octet" >&2; return 1 ;;
    esac
  done
  printf "%d" "$cidr"
}

collect_local_subnets() {
  local route_line iface destination gateway flags refcnt use metric mask mtu window irtt
  local -a allow_ifaces=("$@")
  declare -A allow_iface_map=()
  declare -A seen_subnets=()

  if [[ "${#allow_ifaces[@]}" -gt 0 ]]; then
    for iface in "${allow_ifaces[@]}"; do
      allow_iface_map["$iface"]=1
    done
  fi

  while read -r route_line; do
    [[ -z "$route_line" ]] && continue
    [[ "$route_line" =~ ^Iface[[:space:]] ]] && continue

    read -r iface destination gateway flags refcnt use metric mask mtu window irtt <<<"$route_line"
    [[ -z "${iface:-}" || -z "${destination:-}" || -z "${mask:-}" ]] && continue
    if [[ "${#allow_ifaces[@]}" -gt 0 && -z "${allow_iface_map[$iface]:-}" ]]; then
      continue
    fi
    [[ "$destination" == "00000000" ]] && continue
    [[ "$mask" == "00000000" ]] && continue

    local net_ip mask_ip cidr
    net_ip="$(hex_to_ip "$destination")"
    mask_ip="$(hex_to_ip "$mask")"
    cidr="$(mask_to_cidr "$mask_ip")"

    (( cidr >= 31 )) && continue
    seen_subnets["$net_ip/$cidr"]=1
  done < /proc/net/route

  for subnet in "${!seen_subnets[@]}"; do
    echo "$subnet"
  done | sort -V
}

collect_wifi_ifaces() {
  local wifi_path
  for wifi_path in /sys/class/net/*/wireless; do
    [[ -d "$wifi_path" ]] || continue
    basename "$(dirname "$wifi_path")"
  done | sort -u
}

if ! command -v nmap >/dev/null 2>&1; then
  echo "nmap is required but not found. Install it and re-run." >&2
  exit 1
fi

declare -a subnets=()
declare -a wifi_ifaces=()
if [[ $# -gt 0 ]]; then
  subnets=("$@")
else
  mapfile -t wifi_ifaces < <(collect_wifi_ifaces)
  if [[ "${#wifi_ifaces[@]}" -gt 0 ]]; then
    mapfile -t subnets < <(collect_local_subnets "${wifi_ifaces[@]}")
  else
    mapfile -t subnets < <(collect_local_subnets)
  fi
fi

if [[ "${#subnets[@]}" -eq 0 ]]; then
  echo "No local IPv4 subnets found to scan." >&2
  exit 1
fi

if [[ "${#wifi_ifaces[@]}" -gt 0 ]]; then
  echo "Wi-Fi interfaces:"
  printf '  - %s\n' "${wifi_ifaces[@]}"
fi

echo "Scanning subnets:"
printf '  - %s\n' "${subnets[@]}"

scan_file="$(mktemp)"
trap 'rm -f "$scan_file"' EXIT

for subnet in "${subnets[@]}"; do
  # Prefer ARP scan on local nets; fall back to plain ping scan if needed.
  if ! nmap -sn -PR -n "$subnet" >>"$scan_file" 2>/dev/null; then
    nmap -sn -n "$subnet" >>"$scan_file" 2>/dev/null || true
  fi
done

declare -A oui_vendor=()
declare -A raspberry_ouis=()

if [[ -r "$NMAP_MAC_PREFIXES" ]]; then
  while read -r prefix vendor_rest; do
    [[ "$prefix" =~ ^[0-9A-Fa-f]{6}$ ]] || continue
    prefix="${prefix^^}"
    oui_vendor["$prefix"]="$vendor_rest"
    if [[ "${vendor_rest,,}" == *raspberry* ]]; then
      raspberry_ouis["$prefix"]=1
    fi
  done < "$NMAP_MAC_PREFIXES"
fi

echo
echo "Raspberry Pi candidates:"
found_any=0
found_count=0
declare -A live_hosts=()
declare -A ip_to_mac=()
declare -A ip_to_dev=()
declare -A iface_filter=()
declare -A printed=()

if [[ "${#wifi_ifaces[@]}" -gt 0 ]]; then
  for iface in "${wifi_ifaces[@]}"; do
    iface_filter["$iface"]=1
  done
fi

while IFS= read -r line; do
  if [[ "$line" =~ ^Nmap[[:space:]]scan[[:space:]]report[[:space:]]for[[:space:]] ]]; then
    if [[ "$line" =~ \(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)$ ]]; then
      current_ip="${BASH_REMATCH[1]}"
    else
      current_ip="${line##* }"
      current_ip="${current_ip//[\(\)]/}"
    fi
    [[ "$current_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    live_hosts["$current_ip"]=1
    continue
  fi

  if [[ "$line" =~ ^MAC[[:space:]]Address:[[:space:]]([0-9A-Fa-f:]{17})([[:space:]]\((.*)\))? ]]; then
    mac="${BASH_REMATCH[1]^^}"
    [[ -z "${current_ip:-}" ]] && continue
    ip_to_mac["$current_ip"]="$mac"
  fi
done < "$scan_file"

use_live_hosts=1
if [[ "${#live_hosts[@]}" -eq 0 ]]; then
  use_live_hosts=0
  echo "  (nmap discovery unavailable, using ARP cache fallback)"
fi

while read -r ip hw_type flags mac mask dev; do
  [[ -z "${ip:-}" || -z "${mac:-}" ]] && continue
  [[ "$ip" == "IP" ]] && continue
  if [[ "$use_live_hosts" -eq 1 ]]; then
    [[ -n "${live_hosts[$ip]:-}" ]] || continue
  elif [[ "${#iface_filter[@]}" -gt 0 ]]; then
    [[ -n "${iface_filter[$dev]:-}" ]] || continue
  fi
  [[ "$mac" == "00:00:00:00:00:00" ]] && continue
  ip_to_mac["$ip"]="${mac^^}"
  ip_to_dev["$ip"]="$dev"
done < /proc/net/arp

if [[ "$use_live_hosts" -eq 0 ]]; then
  for ip in "${!ip_to_mac[@]}"; do
    live_hosts["$ip"]=1
  done
fi

for ip in "${!live_hosts[@]}"; do
  mac="${ip_to_mac[$ip]:-}"
  [[ -z "$mac" ]] && continue

  local_oui="${mac//:/}"
  local_oui="${local_oui:0:6}"
  vendor="${oui_vendor[$local_oui]:-Unknown}"
  [[ "${vendor,,}" == *raspberry* || -n "${raspberry_ouis[$local_oui]:-}" ]] || continue

  key="${ip}|${mac}"
  [[ -n "${printed[$key]:-}" ]] && continue
  dev="${ip_to_dev[$ip]:-unknown}"
  printf '  %s\t%s\t%s\t%s\n' "$ip" "$mac" "$dev" "$vendor"
  printed["$key"]=1
  found_any=1
  ((found_count+=1))
done

if [[ "$found_any" -eq 0 ]]; then
  echo "  (none found)"
  echo
  echo "Tip: if your Pi uses randomized MAC, try:"
  echo "  nmap -sn -n ${subnets[0]}"
  echo "Then test likely hosts with: ssh <user>@<ip>"
else
  echo
  echo "Total Raspberry Pis found: $found_count"
fi
