# WatchPort

A lightweight, real-time port monitoring tool for the terminal. Like `watch netstat`, but with powerful filtering, color-coded output, and a responsive layout.

## Features

- **Live refresh** with configurable interval
- **Port filtering** by single port, range, or comma-separated list
- **Protocol filtering** (TCP only, UDP only, or both)
- **IPv4 / IPv6 filtering**
- **Address filtering** with include/exclude patterns for local and remote addresses
- **Grep filtering** across the entire output line (case-insensitive)
- **Sortable** by port, PID, process name, protocol, or status
- **Color-coded** protocol (TCP blue, UDP purple) and status (LISTENING green, ESTABLISHED yellow, TIME_WAIT/CLOSE_WAIT red)
- **Responsive layout** that adapts to terminal width
- **Pause/resume** with scrollable snapshot on pause
- **Cross-platform** support (Windows, Linux, macOS)

## Installation

### From source

```bash
go install github.com/BrianMSon/watchport@latest
```

### Build manually

```bash
git clone https://github.com/BrianMSon/watchport.git
cd watchport
go build -o watchport .
```

## Usage

```
watchport [options] [port]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p` | `""` | Port or port range (e.g. `80`, `8000-9000`, `80,443,8080`) |
| `-a` | `false` | Show all states (default: LISTEN only) |
| `-t` | `false` | TCP only |
| `-u` | `false` | UDP only |
| `-4` | `false` | IPv4 only |
| `-6` | `false` | IPv6 only |
| `-s` | `port` | Sort by: `port`, `pid`, `name`, `proto`, `status` |
| `-d` | `false` | Descending order |
| `-n` | `5.0` | Refresh interval in seconds |
| `-L` | `""` | Local address include filter (comma-separated) |
| `-xL` | `""` | Local address exclude filter (comma-separated) |
| `-R` | `""` | Remote address include filter (comma-separated) |
| `-xR` | `""` | Remote address exclude filter (comma-separated) |
| `-g` | `""` | Grep filter across entire line (case-insensitive, comma-separated) |
| `-xg` | `""` | Grep exclude filter (comma-separated) |
| `-no-header` | `false` | Hide header |

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `p` / `Space` | Pause / Resume |
| `q` | Quit (prints last snapshot) |

## Examples

```bash
# Show all LISTENING ports
watchport

# Monitor port 80
watchport -p 80

# Monitor a port range
watchport -p 8000-9000

# Monitor multiple specific ports
watchport -p 80,443,8080

# Show all connection states for a port range
watchport -p 3000-4000 -a

# TCP only
watchport -t

# UDP only
watchport -u

# IPv4 TCP on port 80
watchport -4 -t -p 80

# Only show local address 127.0.0.1
watchport -L 127.0.0.1

# Exclude wildcard listeners
watchport -xL "0.0.0.0,::"

# Show only remote connections to 192.168.x.x
watchport -R 192.168

# Grep for nginx across all columns
watchport -g nginx

# Exclude lines containing 0.0.0.0 or ::
watchport -xg "0.0.0.0,::"

# Refresh every second
watchport -n 1

# Sort by PID, descending
watchport -s pid -d
```

## Output

```
WatchPort [2m30s] | Ports: 8000-9000 | IPv4+IPv6 | Mode: LISTEN only | Interval: 5.0s | Found: 3
--------------------------------------------------------------------------------------------------------------
PROTO    PORT  LOCAL ADDRESS             REMOTE ADDRESS            STATUS         PID  PROCESS
TCP      8080  0.0.0.0:8080              *:*                       LISTENING      1234  nginx
TCP      8443  0.0.0.0:8443              *:*                       LISTENING      1234  nginx
TCP      9090  127.0.0.1:9090            *:*                       LISTENING      5678  prometheus
```

### Color Coding

**Protocol:**
- Blue: TCP
- Purple: UDP

**Status:**
- Green: LISTENING
- Yellow: ESTABLISHED
- Red: TIME_WAIT, CLOSE_WAIT

## Responsive Layout

The display automatically adapts to your terminal width. The header progressively shortens when the terminal is narrow, and column widths (LOCAL ADDRESS, REMOTE ADDRESS, PROCESS) scale dynamically while fixed-width columns (PROTO, PORT, STATUS, PID) remain constant.

## Requirements

- Go 1.21 or later

## License

[Apache License 2.0](LICENSE)
