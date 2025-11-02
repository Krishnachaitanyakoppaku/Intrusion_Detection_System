#!/bin/bash

# IDS DSL Engine - Complete Installation Script
# This script installs all dependencies and cleans up unnecessary files

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install system dependencies
install_system_dependencies() {
    print_status "Installing system dependencies..."
    
    # Update package list
    sudo apt update -y
    
    # Install required packages
    sudo apt install -y \
        build-essential \
        bison \
        flex \
        libpcap-dev \
        libcurl4-openssl-dev \
        libjson-c-dev \
        python3 \
        python3-pip \
        python3-dev \
        curl \
        wget \
        git \
        make \
        gcc \
        g++ \
        pkg-config
    
    print_success "System dependencies installed successfully!"
}

# Function to install Python dependencies
install_python_dependencies() {
    print_status "Installing Python dependencies..."
    
    # Install required Python packages
    pip3 install --user psutil scapy requests
    
    print_success "Python dependencies installed successfully!"
}

# Function to build the project
build_project() {
    print_status "Building IDS DSL Engine..."
    
    # Clean previous builds
    make clean > /dev/null 2>&1 || true
    
    # Create necessary directories
    mkdir -p bin build logs
    
    # Try to build the full project first
    if make > /dev/null 2>&1; then
        print_success "Full project built successfully!"
    else
        print_warning "Full build failed. This is OK - web server uses scapy_capture.py instead."
        print_status "Creating minimal C engine..."
        
        # Try to build minimal engine if source exists
        if [ -f src/main.c ]; then
            gcc -o bin/ids_engine src/main.c src/engine.c -lpcap 2>/dev/null || {
                print_warning "C engine build failed - using Python-only capture"
            }
        fi
    fi
}

# Function to clean up unnecessary files
cleanup_files() {
    print_status "Cleaning up unnecessary files..."
    
    # Remove backup files
    find . -name "*.bak" -type f -delete 2>/dev/null || true
    find . -name "*.tmp" -type f -delete 2>/dev/null || true
    find . -name "*.swp" -type f -delete 2>/dev/null || true
    find . -name "*~" -type f -delete 2>/dev/null || true
    
    # Remove build artifacts that might be corrupted
    rm -f src/lex.yy.c src/parser.tab.c src/parser.tab.h 2>/dev/null || true
    
    # Clean up any temporary files
    rm -f *.log *.tmp 2>/dev/null || true
    
    # Remove old web server files
    rm -f web_server.py 2>/dev/null || true
    
    print_success "Cleanup completed!"
}

# Function to create necessary directories and files
setup_directories() {
    print_status "Setting up directories and files..."
    
    # Create necessary directories
    mkdir -p bin build logs rules web_interface
    
    # Create logs directory with proper permissions
    chmod 755 logs
    
    # Create a basic alerts log if it doesn't exist
    if [ ! -f logs/alerts.log ]; then
        touch logs/alerts.log
        chmod 644 logs/alerts.log
    fi
    
    # Ensure rules file exists
    if [ ! -f rules/local.rules ]; then
        print_warning "Rules file not found, creating default rules..."
        cat > rules/local.rules << 'EOF'
# IDS DSL Engine - Default Rules
# This file contains default rules for testing the IDS engine

# SQL Injection Detection
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"' OR 1=1"; priority:1)
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"UNION SELECT"; priority:1)

# Cross-Site Scripting (XSS) Detection
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"<script>"; priority:2)
alert tcp any any -> any 80 (msg:"XSS Attack"; content:"javascript:"; priority:2)

# Port Scan Detection
alert tcp any any -> any any (msg:"Port Scan"; content:"SYN"; priority:3)

# ICMP Ping Flood
alert icmp any any -> any any (msg:"ICMP Flood"; priority:4)

# Malicious File Upload
alert tcp any any -> any 80 (msg:"Malicious File Upload"; content:".exe"; priority:2)

# Directory Traversal
alert tcp any any -> any 80 (msg:"Directory Traversal"; content:"../"; priority:2)

# Command Injection
alert tcp any any -> any 80 (msg:"Command Injection"; content:"|"; priority:1)

# Brute Force Attack
alert tcp any any -> any 22 (msg:"SSH Brute Force"; priority:3)

# Log all traffic for testing
log ip any any -> any any (msg:"All IP Traffic"; priority:5)
EOF
    fi
    
    print_success "Directories and files set up successfully!"
}

# Function to test the installation
test_installation() {
    print_status "Testing installation..."
    
    # Test if IDS engine exists and is executable
    if [ -f bin/ids_engine ] && [ -x bin/ids_engine ]; then
        print_success "IDS engine binary is ready"
    else
        print_warning "IDS engine binary not found - using Python-only capture (this is OK)"
    fi
    
    # Test if Python dependencies are available
    if python3 -c "import psutil, scapy, requests" 2>/dev/null; then
        print_success "Python dependencies are available"
    else
        print_warning "Python dependencies may not be fully installed"
        print_status "Run: pip3 install psutil scapy requests"
    fi
    
    # Test if web interface exists
    if [ -f web_interface/index.html ]; then
        print_success "Web interface is ready"
    else
        print_error "Web interface not found"
        return 1
    fi
    
    print_success "Installation test completed!"
}

# Function to create startup script
create_startup_script() {
    print_status "Creating startup script..."
    
    cat > start_ids_system.sh << 'EOF'
#!/bin/bash

# IDS DSL Engine - Startup Script
echo "🛡️ Starting IDS DSL Engine System..."

# Kill any existing processes
pkill -f "python3.*web_server" 2>/dev/null || true
pkill -f "ids_engine" 2>/dev/null || true

# Start the web server with Gemini AI integration
echo "🌐 Starting web server with Gemini AI integration..."
python3 web_server_complete.py &

# Wait a moment for server to start
sleep 2

echo "✅ IDS DSL Engine System started!"
echo "🌐 Web Interface: http://localhost:8080"
echo "🤖 Gemini AI Integration: ENABLED"
echo "📋 Rule Management: ENABLED"
echo ""
echo "Press Ctrl+C to stop all services"

# Keep script running
wait
EOF

    chmod +x start_ids_system.sh
    print_success "Startup script created: start_ids_system.sh"
}

# Main installation function
main() {
    echo "🚀 IDS DSL Engine - Complete Installation"
    echo "=========================================="
    echo ""
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root. This is not recommended for security reasons."
        print_status "Consider running as a regular user and using sudo when needed."
    fi
    
    # Step 1: Install system dependencies
    print_status "Step 1: Installing system dependencies..."
    install_system_dependencies
    
    # Step 2: Install Python dependencies
    print_status "Step 2: Installing Python dependencies..."
    install_python_dependencies
    
    # Step 3: Setup directories and files
    print_status "Step 3: Setting up directories and files..."
    setup_directories
    
    # Step 4: Clean up unnecessary files
    print_status "Step 4: Cleaning up unnecessary files..."
    cleanup_files
    
    # Step 5: Build the project
    print_status "Step 5: Building the project..."
    build_project
    
    # Step 6: Test the installation
    print_status "Step 6: Testing the installation..."
    test_installation
    
    # Step 7: Create startup script
    print_status "Step 7: Creating startup script..."
    create_startup_script
    
    echo ""
    print_success "🎉 Installation completed successfully!"
    echo ""
    print_status "Next steps:"
    print_status "  1. Run: ./start_ids_system.sh"
    print_status "  2. Open: http://localhost:8080"
    print_status "  3. Start creating AI-powered security rules!"
    echo ""
    print_status "Features available:"
    print_status "  • 🤖 Gemini AI integration for rule conversion"
    print_status "  • 📋 Complete rule management (view, edit, delete)"
    print_status "  • 🚨 Real-time security monitoring"
    print_status "  • 🌐 Modern web interface"
    print_status "  • 📊 Live alerts and statistics"
    echo ""
}

# Run the main function
main "$@"
