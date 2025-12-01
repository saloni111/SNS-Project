# DNS Tunneling Detection System

## What I Built
I created a DNS tunneling detection system that actually explains why domains look suspicious, instead of just throwing alerts at security teams. After researching the problem and finding that existing tools generate too many false positives with no explanations, I built something better.

## Key Features
- **Transparent Detection**: Every alert explains exactly why a domain is flagged
- **Hybrid Approach**: Combines fast rule-based detection with ML anomaly detection  
- **Real-time Analysis**: Processes DNS traffic as it happens
- **Interactive Dashboard**: Built with Streamlit for easy exploration
- **High Accuracy**: 89.9% F1-score with realistic testing

## How I Organized the Code
```
├── src/                    # My source code
│   ├── capture/           # DNS packet capture and parsing
│   ├── features/          # Feature extraction (40+ features!)
│   ├── detection/         # Hybrid detection engine
│   ├── dashboard/         # Interactive web interface
│   └── utils/             # Data generation and utilities
├── data/                  # DNS traffic database
├── tests/                 # Evaluation framework
├── docs/                  # Project documentation
├── requirements.txt       # Python dependencies
└── main.py               # Command-line interface
```

## Quick Start
```bash
# Set up virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Generate test data
python main.py generate --legitimate 500 --tunneling 100

# Train the model
python main.py train

# Launch dashboard
python main.py dashboard
# Opens at http://localhost:8501
```

## What You'll See
The dashboard shows real-time DNS analysis with clear explanations like:
```
🚨 zA6kbO5IseqU8vwPjzYLJMrY0NUpG.tunnel8218.com (Confidence: 0.56)
Alerts:
• High domain entropy: 4.73
• Base64 pattern detected
• High domain diversity: 1.00


