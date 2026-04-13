# Network Aggregator (Go)

A high-performance tool for parsing, analyzing, and aggregating large lists of IPv4 CIDR networks.

## Features

- IPv4 CIDR parsing and validation
- Network comparison (subnet/supernet detection)
- Aggressive aggregation of overlapping networks
- Smart grouping by IP octets
- In-place file processing (safe temp-file replace)
- Large dataset optimization

## How it works

The tool:

1. Reads a file containing CIDR networks
2. Parses and validates each entry
3. Groups networks by IP octets
4. Detects frequent IP ranges
5. Attempts aggregation into supernets
6. Sorts final result
7. Writes back to the same file safely

## Docker build

```sh
git clone https://github.com/attaattaatta/netagg.git
cd netagg/
docker run --rm -v "$PWD":/app -w /app golang:alpine go build -ldflags="-s -w" -o netagg netagg.go
```

## Usage

```bash

networks="networks.txt"
for AS in 1111 2222 3333 4444; do
	echo "Running bgpq3 AS${AS}"
	until timeout 5 bgpq3 AS${AS} | awk '{print $5}' >> "$networks"; do
		echo "Retrying bgpq3 AS${AS}..."
		sleep 2
	done
done

tmp=$(mktemp)
aggregate -q "$networks" > "$tmp" 2>/dev/null || aggregate6 "$networks" > "$tmp" 2>/dev/null
mv "$tmp" "$networks"

#inplace edit
netagg "$networks" &> /dev/null 
```