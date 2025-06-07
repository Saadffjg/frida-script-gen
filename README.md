
# FridaScriptGen

Generate Frida bypass scripts for Android root and SSL checks.

<img width="544" alt="image" src="https://github.com/user-attachments/assets/72dbf90d-9cf7-462c-a5c7-430fe4265a81" />


## Features
- Analyzes APK for root/SSL detections
- Creates tailored Frida scripts

> **Note:** This is the lite version of the script.


## Usage
```bash
python3 frida-script-gen.py <apk_file> [-o output_name]
```

## Requirements
- Python 3.X
- androguard==3.3.5
- apktool
- rich

## Installation
```bash
pip3 install androguard==3.3.5 rich
```

## Example
```bash
python3 frida-script-gen.py app.apk
frida -U -f com.example.app -l bypass_script.js
```
