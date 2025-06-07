
# FridaScriptGen

It scans an APK’s Smali code for root-detection and SSL-pinning patterns and then automatically creates Frida scripts to bypass these security checks.


<img width="544" alt="image" src="https://github.com/user-attachments/assets/72dbf90d-9cf7-462c-a5c7-430fe4265a81" />

<img width="567" alt="image" src="https://github.com/user-attachments/assets/2e780eb5-fcdc-41ca-b1c9-7c8550d80b67" />


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
