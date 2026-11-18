#!/usr/bin/env bash
# ==============================================================================
# Morph Core — One-Click Automated Installer for Linux
# Repository: https://github.com/FrgfA4ftfzTdfyyyr5f6tESD3/fast-udp-tunnel
# ==============================================================================

set -e

# ANSI Color Codes
CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_GREEN="\033[38;2;16;185;129m"
CLR_BLUE="\033[38;2;59;130;246m"
CLR_PURPLE="\033[38;2;139;92;246m"
CLR_AMBER="\033[38;2;245;158;11m"
CLR_RED="\033[38;2;239;68;68m"
CLR_GRAY="\033[38;2;148;163;184m"

echo -e "${CLR_GREEN}${CLR_BOLD}"
cat << 'EOF'
 __  __  ___  ____  ____  _   _    ____ ___  ____  _____ 
|  \/  |/ _ \|  _ \|  _ \| | | |  / ___/ _ \|  _ \| ____|
| |\/| | | | | |_) | |_) | |_| | | |  | | | | |_) |  _|  
| |  | | |_| |  _ <|  __/|  _  | | |__| |_| |  _ <| |___ 
|_|  |_|\___/|_| \_\_|   |_| |_|  \____\___/|_| \_\_____|
EOF
echo -e "${CLR_RESET}"
echo -e "${CLR_BLUE}  Morph Core — Ultra-Fast Layer-3 RAW IP UDP Tunnel Server${CLR_RESET}"
echo -e "${CLR_GRAY}  Automated Installer & Service Manager | v8.7.0${CLR_RESET}"
echo "=================================================================="

# 1. Root Verification
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${CLR_RED}[ERROR] This installer must be run as root (use sudo or su).${CLR_RESET}"
    exit 1
fi

# 2. Architecture Verification
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        TARGET_ARCH="x86_64"
        BINARY_FILE="morph-server-linux-x86_64"
        ;;
    *)
        echo -e "${CLR_RED}[ERROR] Architecture '$ARCH' is not supported by the precompiled binary.${CLR_RESET}"
        echo -e "${CLR_GRAY}Precompiled binary supports x86_64 (Linux Musl Static).${CLR_RESET}"
        exit 1
        ;;
esac

# 3. Detect Package Manager & Install Minimum Dependencies
echo -e "\n${CLR_BLUE}[1/6] Checking system dependencies...${CLR_RESET}"
MISSING_PKGS=""
if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
    MISSING_PKGS="$MISSING_PKGS curl"
fi
if ! command -v ip &>/dev/null; then
    MISSING_PKGS="$MISSING_PKGS iproute2"
fi
if ! command -v iptables &>/dev/null; then
    MISSING_PKGS="$MISSING_PKGS iptables"
fi

if [ -n "$MISSING_PKGS" ]; then
    echo -e "${CLR_AMBER}Installing required packages:${MISSING_PKGS}...${CLR_RESET}"
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq $MISSING_PKGS
    elif command -v apk &>/dev/null; then
        apk add --no-cache $MISSING_PKGS ip6tables
    elif command -v dnf &>/dev/null; then
        dnf install -y -q $MISSING_PKGS
    elif command -v yum &>/dev/null; then
        yum install -y -q $MISSING_PKGS
    fi
fi

# 4. Auto-detect Public IPv4 & IPv6
echo -e "\n${CLR_BLUE}[2/6] Detecting server network endpoints...${CLR_RESET}"

FETCH_CMD="curl -fsSL --max-time 3"
if ! command -v curl &>/dev/null; then
    FETCH_CMD="wget -qO- --timeout=3"
fi

AUTODETECT_V4=$($FETCH_CMD -4 https://api.ipify.org 2>/dev/null || $FETCH_CMD -4 https://ifconfig.me/ip 2>/dev/null || ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1 || echo "")
AUTODETECT_V6=$($FETCH_CMD -6 https://api64.ipify.org 2>/dev/null || $FETCH_CMD -6 https://ifconfig.co/ip 2>/dev/null || ip -6 addr show scope global | grep -oP '(?<=inet6\s)[a-f0-9:]+' | head -n1 || echo "")

# If running in interactive terminal (not piped from curl)
if [ -t 0 ] && [ -t 1 ]; then
    read -rp "Public IPv4 endpoint [$AUTODETECT_V4]: " INPUT_V4
    SERVER_V4="${INPUT_V4:-$AUTODETECT_V4}"

    read -rp "Public IPv6 endpoint [$AUTODETECT_V6]: " INPUT_V6
    SERVER_V6="${INPUT_V6:-$AUTODETECT_V6}"

    read -rp "Primary UDP Tunnel Port [7190]: " INPUT_PORT
    PRIMARY_PORT="${INPUT_PORT:-7190}"

    read -rp "Admin Web Dashboard Port [9090]: " INPUT_ADMIN_PORT
    ADMIN_PORT="${INPUT_ADMIN_PORT:-9090}"
else
    SERVER_V4="$AUTODETECT_V4"
    SERVER_V6="$AUTODETECT_V6"
    PRIMARY_PORT="7190"
    ADMIN_PORT="9090"
fi

echo -e "  IPv4: ${CLR_GREEN}${SERVER_V4:-None}${CLR_RESET}"
echo -e "  IPv6: ${CLR_GREEN}${SERVER_V6:-None}${CLR_RESET}"
echo -e "  Primary UDP Port: ${CLR_GREEN}${PRIMARY_PORT}${CLR_RESET}"
echo -e "  Admin Web Port  : ${CLR_GREEN}${ADMIN_PORT}${CLR_RESET}"

# 5. Download Precompiled Static Musl Binary
echo -e "\n${CLR_BLUE}[3/6] Downloading Morph Core Server binary (${TARGET_ARCH})...${CLR_RESET}"
INSTALL_BIN="/usr/local/bin/morph-server"
GITHUB_REPO="FrgfA4ftfzTdfyyyr5f6tESD3/fast-udp-tunnel"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v8.7.0/${BINARY_FILE}"
BACKUP_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/${BINARY_FILE}"

# Stop existing service if running
if command -v systemctl &>/dev/null && systemctl is-active --quiet morph-server 2>/dev/null; then
    echo -e "${CLR_GRAY}Stopping active morph-server service for update...${CLR_RESET}"
    systemctl stop morph-server
elif command -v rc-service &>/dev/null && rc-service morph-server status &>/dev/null; then
    rc-service morph-server stop
fi

TMP_BIN="/tmp/${BINARY_FILE}.$$"
if command -v curl &>/dev/null; then
    curl -fsSL --progress-bar -o "$TMP_BIN" "$DOWNLOAD_URL" || curl -fsSL --progress-bar -o "$TMP_BIN" "$BACKUP_URL"
else
    wget -q --show-progress -O "$TMP_BIN" "$DOWNLOAD_URL" || wget -q --show-progress -O "$TMP_BIN" "$BACKUP_URL"
fi

if [ ! -s "$TMP_BIN" ]; then
    echo -e "${CLR_RED}[ERROR] Failed to download server binary from GitHub Releases.${CLR_RESET}"
    exit 1
fi

mv "$TMP_BIN" "$INSTALL_BIN"
chmod +x "$INSTALL_BIN"
echo -e "${CLR_GREEN}Installed: ${INSTALL_BIN}${CLR_RESET}"

# 6. Setup Configuration Directory
echo -e "\n${CLR_BLUE}[4/6] Initializing server configuration...${CLR_RESET}"
CONF_DIR="/etc/morph"
mkdir -p "$CONF_DIR"

CONF_FILE="${CONF_DIR}/morph.conf"
cat > "$CONF_FILE" << EOF
# Morph Core Server Configuration
PRIMARY_PORT=${PRIMARY_PORT}
ADMIN_PORT=${ADMIN_PORT}
SERVER_V4="${SERVER_V4}"
SERVER_V6="${SERVER_V6}"
USERS_COUNT=10
EOF
chmod 600 "$CONF_FILE"

# 7. Create Service (systemd or OpenRC)
echo -e "\n${CLR_BLUE}[5/6] Configuring auto-start service...${CLR_RESET}"

INIT_SYSTEM="unknown"
if [ -d /run/systemd/system ] || command -v systemctl &>/dev/null; then
    INIT_SYSTEM="systemd"
    SERVICE_FILE="/etc/systemd/system/morph-server.service"
    cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Morph Core — Fast Layer-3 UDP Tunnel Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/etc/morph
EnvironmentFile=/etc/morph/morph.conf
ExecStart=/usr/local/bin/morph-server --admin-port ${ADMIN_PORT} --server-v4 "${SERVER_V4}" --server-v6 "${SERVER_V6}" -p ${PRIMARY_PORT} -u ${USERS_COUNT}
Restart=always
RestartSec=3
LimitNOFILE=1048576
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable morph-server.service >/dev/null 2>&1
    systemctl restart morph-server.service
    sleep 2

    if systemctl is-active --quiet morph-server; then
        echo -e "${CLR_GREEN}systemd service started and active!${CLR_RESET}"
    else
        echo -e "${CLR_RED}[WARN] systemd service failed to start immediately. Check 'journalctl -u morph-server'.${CLR_RESET}"
    fi

elif [ -f /sbin/openrc ] || [ -d /etc/init.d ]; then
    INIT_SYSTEM="openrc"
    SERVICE_FILE="/etc/init.d/morph-server"
    cat > "$SERVICE_FILE" << 'EOF'
#!/sbin/openrc-run

name="morph-server"
description="Morph Core Fast Layer-3 UDP Tunnel Server"
directory="/etc/morph"
command="/usr/local/bin/morph-server"
command_background="yes"
pidfile="/run/morph-server.pid"

depend() {
    need net
    after firewall
}

start_pre() {
    if [ -f /etc/morph/morph.conf ]; then
        . /etc/morph/morph.conf
    fi
    command_args="--admin-port ${ADMIN_PORT:-9090} --server-v4 ${SERVER_V4} --server-v6 ${SERVER_V6} -p ${PRIMARY_PORT:-7190} -u ${USERS_COUNT:-10}"
}
EOF
    chmod +x "$SERVICE_FILE"
    rc-update add morph-server default >/dev/null 2>&1
    rc-service morph-server restart
    echo -e "${CLR_GREEN}OpenRC service started and active!${CLR_RESET}"
fi

# 8. Create Management CLI `/usr/local/bin/morph`
echo -e "\n${CLR_BLUE}[6/6] Creating management CLI '/usr/local/bin/morph'...${CLR_RESET}"
CLI_TOOL="/usr/local/bin/morph"

cat > "$CLI_TOOL" << 'EOF'
#!/usr/bin/env bash
# Morph Core Management CLI

CLR_RESET="\033[0m"
CLR_BOLD="\033[1m"
CLR_GREEN="\033[38;2;16;185;129m"
CLR_BLUE="\033[38;2;59;130;246m"
CLR_AMBER="\033[38;2;245;158;11m"
CLR_RED="\033[38;2;239;68;68m"
CLR_GRAY="\033[38;2;148;163;184m"

CONF_FILE="/etc/morph/morph.conf"
SERVER_CFG="/etc/morph/server_config.json"
USERS_FILE="/etc/morph/users.json"

show_info() {
    echo -e "${CLR_GREEN}${CLR_BOLD}==================================================================${CLR_RESET}"
    echo -e "${CLR_GREEN}${CLR_BOLD}  MORPH CORE — EDGE SERVER & ADMIN CONSOLE${CLR_RESET}"
    echo -e "${CLR_GREEN}${CLR_BOLD}==================================================================${CLR_RESET}"

    if [ -f "$CONF_FILE" ]; then
        . "$CONF_FILE"
    fi

    if [ -f "$SERVER_CFG" ]; then
        SECRET_PREFIX=$(grep -o '"secret_prefix": *"[^"]*"' "$SERVER_CFG" | head -n1 | cut -d'"' -f4)
        ADMIN_USER=$(grep -o '"admin_user": *"[^"]*"' "$SERVER_CFG" | head -n1 | cut -d'"' -f4)
        ADMIN_PASS=$(grep -o '"admin_pass": *"[^"]*"' "$SERVER_CFG" | head -n1 | cut -d'"' -f4)
    fi

    CONSOLE_PATH="${SECRET_PREFIX:-/v2/sys/telemetry/auth}/console"
    APORT="${ADMIN_PORT:-9090}"

    if [ -n "$SERVER_V4" ]; then
        echo -e "  Admin URL (IPv4) : ${CLR_BLUE}http://${SERVER_V4}:${APORT}${CONSOLE_PATH}${CLR_RESET}"
    fi
    if [ -n "$SERVER_V6" ]; then
        echo -e "  Admin URL (IPv6) : ${CLR_BLUE}http://[${SERVER_V6}]:${APORT}${CONSOLE_PATH}${CLR_RESET}"
    fi
    echo -e "  Username         : ${CLR_BOLD}${ADMIN_USER:-admin}${CLR_RESET}"
    echo -e "  Password         : ${CLR_BOLD}${ADMIN_PASS:-[Check /etc/morph/server_config.json]}${CLR_RESET}"
    echo -e "  Primary UDP Port : ${CLR_GREEN}${PRIMARY_PORT:-7190}${CLR_RESET}"
    echo -e "  All UDP Ports    : ${CLR_GRAY}7190, 443, 3478, 19132, 27015, 27020, 7500, 8801, 3389, 50000, 5353, 4500, 6881, 53${CLR_RESET}"
    echo -e "${CLR_GREEN}${CLR_BOLD}==================================================================${CLR_RESET}"

    # Print first token if available
    if [ -f "$USERS_FILE" ]; then
        FIRST_TOK=$(grep -o '"token_uri": *"[^"]*"' "$USERS_FILE" | head -n1 | cut -d'"' -f4)
        if [ -n "$FIRST_TOK" ]; then
            echo -e "\n${CLR_AMBER}Default Client Token (User #1):${CLR_RESET}"
            echo -e "${CLR_GRAY}${FIRST_TOK}${CLR_RESET}\n"
        fi
    fi
}

case "$1" in
    status)
        if command -v systemctl &>/dev/null; then
            systemctl status morph-server
        elif command -v rc-service &>/dev/null; then
            rc-service morph-server status
        fi
        ;;
    restart)
        if command -v systemctl &>/dev/null; then
            systemctl restart morph-server
        elif command -v rc-service &>/dev/null; then
            rc-service morph-server restart
        fi
        echo "morph-server restarted."
        ;;
    stop)
        if command -v systemctl &>/dev/null; then
            systemctl stop morph-server
        elif command -v rc-service &>/dev/null; then
            rc-service morph-server stop
        fi
        echo "morph-server stopped."
        ;;
    start)
        if command -v systemctl &>/dev/null; then
            systemctl start morph-server
        elif command -v rc-service &>/dev/null; then
            rc-service morph-server start
        fi
        echo "morph-server started."
        ;;
    logs)
        if command -v journalctl &>/dev/null; then
            journalctl -u morph-server -f -n 50
        else
            echo "Logs are sent to syslog. Check /var/log/messages or /var/log/syslog"
        fi
        ;;
    tokens|users)
        if [ -f "$USERS_FILE" ]; then
            grep -E '"(name|token_uri|assigned_ipv4)"' "$USERS_FILE"
        else
            echo "No users file found at $USERS_FILE"
        fi
        ;;
    info|"")
        show_info
        ;;
    uninstall)
        read -rp "Are you sure you want to uninstall Morph Core Server? (y/N): " CONFIRM
        if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
            if command -v systemctl &>/dev/null; then
                systemctl stop morph-server 2>/dev/null || true
                systemctl disable morph-server 2>/dev/null || true
                rm -f /etc/systemd/system/morph-server.service
                systemctl daemon-reload
            elif command -v rc-service &>/dev/null; then
                rc-service morph-server stop 2>/dev/null || true
                rc-update del morph-server default 2>/dev/null || true
                rm -f /etc/init.d/morph-server
            fi
            rm -f /usr/local/bin/morph-server /usr/local/bin/morph
            echo "Morph Core Server uninstalled. Data in /etc/morph kept intact."
        fi
        ;;
    *)
        echo "Usage: morph {info|status|restart|stop|start|logs|tokens|uninstall}"
        ;;
esac
EOF

chmod +x "$CLI_TOOL"

# 9. Print Final Success Summary
echo -e "\n${CLR_GREEN}${CLR_BOLD}[SUCCESS] Morph Core Server installed and running!${CLR_RESET}\n"
$CLI_TOOL info

echo -e "${CLR_GRAY}Management commands:${CLR_RESET}"
echo -e "  ${CLR_BOLD}morph${CLR_RESET}         - Show admin console URL, password & token"
echo -e "  ${CLR_BOLD}morph status${CLR_RESET}  - Check tunnel and interface status"
echo -e "  ${CLR_BOLD}morph restart${CLR_RESET} - Restart server service"
echo -e "  ${CLR_BOLD}morph logs${CLR_RESET}    - Tail live server logs"
echo -e "  ${CLR_BOLD}morph tokens${CLR_RESET}  - View active subscriber tokens\n"
