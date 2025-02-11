#!/usr/bin/env python3

####################################################################
# dnsbls.py - DNSBL-checker-python-utility                         #
# copyright: (c) 2025 Anders Aarvik                                #
# author: Anders Aarvik (aarvik92@gmail.com) and contributors      #
# license: GPL licensed. See LICENSE                               #
# description: I was just a bit tired of web interfaces            #
####################################################################

import socket
import argparse
import concurrent.futures
import ipaddress

def load_dnsbls(filename):
    dnsbls = []
    try:
        with open(filename, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    dnsbls.append(line)
    except Exception as e:
        raise IOError(f"Error reading DNSBL file '{filename}': {e}")
    return dnsbls

def resolve_target(target):
    try:
        ip_obj = ipaddress.IPv4Address(target)
        return str(ip_obj)
    except ipaddress.AddressValueError:
        try:
            ip = socket.gethostbyname(target)
            print(f"Resolved domain '{target}' to IP {ip}")
            return ip
        except socket.gaierror as e:
            raise ValueError(f"Could not resolve domain '{target}': {e}")

def reverse_ip(ip):
    parts = ip.strip().split('.')
    if len(parts) != 4:
        raise ValueError("Invalid IPv4 address. Please provide an address like '1.2.3.4'.")
    return '.'.join(parts[::-1])

def check_dnsbl(dnsbl, reversed_ip):
    query = f"{reversed_ip}.{dnsbl}"
    try:
        result = socket.gethostbyname(query)
        return dnsbl, True, result
    except socket.gaierror:
        return dnsbl, False, None

def main():
    parser = argparse.ArgumentParser(
        description="Check if an IPv4 address or a domain is listed on various DNS blacklists."
    )
    parser.add_argument("target", help="The IPv4 address or domain to check (e.g., 1.2.3.4 or example.com)")
    parser.add_argument(
        "--dnsbls-file",
        default="dnsbls.txt",
        help="Path to a file containing DNSBL domains (default: dnsbls.txt)"
    )
    args = parser.parse_args()

    try:
        dnsbls = load_dnsbls(args.dnsbls_file)
        if not dnsbls:
            print(f"No DNSBLs found in {args.dnsbls_file}.")
            return
    except Exception as e:
        print(e)
        return

    try:
        ip = resolve_target(args.target)
    except ValueError as e:
        print(f"Error: {e}")
        return

    try:
        reversed_ip = reverse_ip(ip)
    except ValueError as e:
        print(f"Error: {e}")
        return

    print(f"\nChecking blacklist status for {ip} using {len(dnsbls)} DNSBL(s)...\n")

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(check_dnsbl, dnsbl, reversed_ip): dnsbl for dnsbl in dnsbls}

        for future in concurrent.futures.as_completed(futures):
            dnsbl = futures[future]
            try:
                dnsbl, is_listed, response = future.result()
                if is_listed:
                    print(f"[LISTED] {ip} is blacklisted at {dnsbl} (response: {response})")
                else:
                    print(f"[OK]     {ip} is NOT blacklisted at {dnsbl}")
            except Exception as exc:
                print(f"Error checking {dnsbl}: {exc}")

if __name__ == '__main__':
    main()
