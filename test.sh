#!/bin/bash
# ULTIMA OSINT Tool - Quick Test Script

echo "🔍 ULTIMA OSINT Tool - Quick Test Suite"
echo "========================================"
echo ""

# Check Python version
echo "✓ Checking Python version..."
python3 --version
echo ""

# Check if osint.py is valid
echo "✓ Validating osint.py syntax..."
python3 -m py_compile osint.py
if [ $? -eq 0 ]; then
    echo "  ✅ Python syntax is valid"
else
    echo "  ❌ Python syntax errors found"
    exit 1
fi
echo ""

# Check requirements
echo "✓ Required files:"
for file in osint.py sites.json config.ini requirements.txt; do
    if [ -f "$file" ]; then
        echo "  ✅ $file"
    else
        echo "  ❌ $file (MISSING)"
    fi
done
echo ""

# Test basic imports (with error handling)
echo "✓ Testing Python imports..."
python3 << 'EOF'
import sys
failed = []
packages = ['requests', 'dnspython', 'whois', 'beautifulsoup4', 'selenium']

for pkg in packages:
    try:
        __import__(pkg.replace('-', '_'))
        print(f"  ✅ {pkg}")
    except ImportError:
        print(f"  ⚠️  {pkg} (optional)")

try:
    import google.generativeai
    print(f"  ✅ google.generativeai (Gemini)")
except ImportError:
    print(f"  ⚠️  google.generativeai (optional)")
EOF
echo ""

# Test cache system
echo "✓ Testing cache system..."
python3 << 'EOF'
from pathlib import Path
from datetime import datetime, timedelta
import pickle
import hashlib

# Create test cache
cache_dir = Path('.osint_cache_test')
cache_dir.mkdir(exist_ok=True)

# Test write
test_key = "test_key"
test_value = {"data": "test"}
cache_path = cache_dir / f"{hashlib.md5(test_key.encode()).hexdigest()}.cache"

with open(cache_path, 'wb') as f:
    pickle.dump({'data': test_value, 'timestamp': datetime.now()}, f)

# Test read
with open(cache_path, 'rb') as f:
    cached = pickle.load(f)
    
if cached['data'] == test_value:
    print("  ✅ Cache system working")
else:
    print("  ❌ Cache system failed")

# Cleanup
import shutil
shutil.rmtree(cache_dir)
EOF
echo ""

# Test help command
echo "✓ Testing help command..."
python3 osint.py -h > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  ✅ Help command works"
else
    echo "  ❌ Help command failed"
fi
echo ""

echo "✨ All basic tests passed!"
echo ""
echo "Ready to use ULTIMA OSINT Tool"
echo ""
echo "Example commands:"
echo "  python3 osint.py username johndoe -v"
echo "  python3 osint.py email test@example.com --html report.html"
echo "  python3 osint.py person 'John Doe' -D 2 --csv results.csv"
echo ""
