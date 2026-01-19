#!/bin/bash
#
# Network Sniffer Setup Script
# Sets up the network sniffer tool on a fresh machine
#
# Usage: ./setup.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

# Detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            OS="debian"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
        elif [ -f /etc/arch-release ]; then
            OS="arch"
        else
            OS="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    else
        OS="unknown"
    fi
    echo $OS
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install system dependencies based on OS
install_system_deps() {
    local os=$1
    print_status "Installing system dependencies for $os..."

    case $os in
        debian)
            sudo apt-get update
            sudo apt-get install -y \
                python3 \
                python3-pip \
                python3-venv \
                libpcap-dev \
                tcpdump \
                net-tools
            ;;
        redhat)
            sudo yum install -y epel-release || true
            sudo yum install -y \
                python3 \
                python3-pip \
                libpcap-devel \
                tcpdump \
                net-tools
            ;;
        arch)
            sudo pacman -Sy --noconfirm \
                python \
                python-pip \
                libpcap \
                tcpdump \
                net-tools
            ;;
        macos)
            # Check for Homebrew
            if ! command_exists brew; then
                print_status "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            # libpcap is pre-installed on macOS, but ensure python3 is available
            brew install python3 || true
            ;;
        *)
            print_warning "Unknown OS. Please install manually:"
            print_warning "  - Python 3.9+"
            print_warning "  - libpcap development files"
            print_warning "  - pip"
            return 1
            ;;
    esac
    print_success "System dependencies installed"
}

# Check Python version
check_python() {
    print_status "Checking Python version..."

    if command_exists python3; then
        PYTHON_CMD="python3"
    elif command_exists python; then
        PYTHON_CMD="python"
    else
        print_error "Python not found. Please install Python 3.9+"
        return 1
    fi

    # Check version
    PYTHON_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.major)')
    PYTHON_MINOR=$($PYTHON_CMD -c 'import sys; print(sys.version_info.minor)')

    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
        print_error "Python 3.9+ required. Found: $PYTHON_VERSION"
        return 1
    fi

    print_success "Python $PYTHON_VERSION found ($PYTHON_CMD)"
}

# Create virtual environment
create_venv() {
    print_status "Creating virtual environment..."

    if [ -d "venv" ]; then
        print_warning "Virtual environment already exists"
        read -p "Recreate? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf venv
        else
            return 0
        fi
    fi

    $PYTHON_CMD -m venv venv
    print_success "Virtual environment created"
}

# Install Python dependencies
install_python_deps() {
    print_status "Installing Python dependencies..."

    # Activate virtual environment
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip

    # Install the package in development mode
    pip install -e .

    # Install additional dev dependencies if needed
    pip install pytest pytest-cov

    print_success "Python dependencies installed"
}

# Setup permissions (for packet capture)
setup_permissions() {
    local os=$1
    print_status "Setting up capture permissions..."

    case $os in
        debian|redhat|arch|linux)
            print_warning "On Linux, you have two options for packet capture:"
            echo ""
            echo "  Option 1: Run with sudo (recommended for testing)"
            echo "    sudo ./sniff.sh diagnose -i eth0"
            echo ""
            echo "  Option 2: Add CAP_NET_RAW capability (for non-root use)"
            echo "    sudo setcap cap_net_raw+ep \$(which python3)"
            echo ""
            read -p "Add CAP_NET_RAW capability now? [y/N] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                PYTHON_PATH=$(which $PYTHON_CMD)
                sudo setcap cap_net_raw+ep "$PYTHON_PATH"
                print_success "Capability added to $PYTHON_PATH"
            fi
            ;;
        macos)
            print_warning "On macOS, you need to run with sudo for packet capture:"
            echo "    sudo ./sniff.sh diagnose -i en0"
            echo ""
            echo "  Or grant BPF access (advanced):"
            echo "    sudo chgrp admin /dev/bpf*"
            echo "    sudo chmod g+r /dev/bpf*"
            ;;
    esac
}

# Create launcher script
create_launcher() {
    print_status "Creating launcher script..."

    # Get the directory of this script
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    cat > sniff.sh << EOF
#!/bin/bash
# Network Sniffer Launcher
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="\$SCRIPT_DIR:\$PYTHONPATH"

# Use virtual environment if available
if [ -f "\$SCRIPT_DIR/venv/bin/python" ]; then
    exec "\$SCRIPT_DIR/venv/bin/python" -m network_sniffer.cli "\$@"
else
    exec python3 -m network_sniffer.cli "\$@"
fi
EOF
    chmod +x sniff.sh
    print_success "Launcher script created: ./sniff.sh"
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."

    source venv/bin/activate

    # Try importing the module
    if $PYTHON_CMD -c "from network_sniffer.cli import main; print('Import OK')" 2>/dev/null; then
        print_success "Module import successful"
    else
        print_error "Module import failed"
        return 1
    fi

    # Check scapy
    if $PYTHON_CMD -c "from scapy.all import sniff; print('Scapy OK')" 2>/dev/null; then
        print_success "Scapy is working"
    else
        print_error "Scapy import failed"
        return 1
    fi

    # Try listing interfaces
    print_status "Testing interface detection..."
    ./sniff.sh list || true
}

# Print usage instructions
print_usage() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}Installation Complete!${NC}"
    echo "=========================================="
    echo ""
    echo "Quick Start:"
    echo ""
    echo "  1. List available interfaces:"
    echo "     ./sniff.sh list"
    echo ""
    echo "  2. Run diagnostic (requires sudo):"
    echo "     sudo ./sniff.sh diagnose -i <interface> -d 30"
    echo ""
    echo "  3. Example for WiFi (macOS):"
    echo "     sudo ./sniff.sh diagnose -i en0 -d 30"
    echo ""
    echo "  4. Example for Ethernet (Linux):"
    echo "     sudo ./sniff.sh diagnose -i eth0 -d 30"
    echo ""
    echo "  5. Compare two interfaces:"
    echo "     sudo ./sniff.sh diagnose -i en0,en1 -d 60"
    echo ""
    echo "Reports will be saved to ./reports/"
    echo ""
    echo "For help: ./sniff.sh --help"
    echo ""
}

# Main installation flow
main() {
    echo ""
    echo "=========================================="
    echo "  Network Sniffer Setup"
    echo "=========================================="
    echo ""

    # Detect OS
    OS=$(detect_os)
    print_status "Detected OS: $OS"

    # Install system dependencies
    install_system_deps $OS

    # Check Python
    check_python

    # Create virtual environment
    create_venv

    # Install Python dependencies
    install_python_deps

    # Create launcher
    create_launcher

    # Setup permissions
    setup_permissions $OS

    # Verify installation
    verify_installation

    # Print usage
    print_usage
}

# Run main function
main "$@"
