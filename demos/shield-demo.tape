# VHS tape for the Shield demo GIF
#
# Prerequisites:
#   1. cargo build --release -p vellaveto-proxy
#   2. brew install vhs  (or: go install github.com/charmbracelet/vhs@latest)
#
# Record:
#   cd demos && vhs shield-demo.tape
#
# Output: shield-demo.gif (embed in README)

Output shield-demo.gif

Set FontSize 16
Set Width 900
Set Height 520
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 16

# Start the demo
Type "# VellaVeto — MCP Tool Firewall"
Enter
Sleep 500ms
Type "# One command protects your AI coding assistant"
Enter
Sleep 800ms

Type "python3 demo-client.py ../target/release/vellaveto-proxy --protect shield -- python3 mock-mcp-server.py"
Enter
Sleep 6s

# Wait for all output to appear
Sleep 2s
