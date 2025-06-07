#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import re
import os
import json
import shutil
import subprocess
import argparse
import time
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Set, Tuple, Optional
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import print as rprint

VERSION = "1.0"
AUTHOR = "Sandeep Wawdane"

console = Console()

@dataclass
class Detection:
    class_name: str
    method_name: str
    method_signature: str
    detection_type: str
    bypass_code: str
    overloads: List[str] = None
    detected_strings: List[str] = None

class SmaliPatternMatcher:
    
    COMMON_ROOT_PATHS = [
        "/data/local/bin/su", "/data/local/su", "/data/local/xbin/su",
        "/dev/com.koushikdutta.superuser.daemon/", "/sbin/su",
        "/system/app/Superuser.apk", "/system/bin/failsafe/su",
        "/system/bin/su", "/su/bin/su", "/system/etc/init.d/99SuperSUDaemon",
        "/system/sd/xbin/su", "/system/xbin/busybox", "/system/xbin/daemonsu",
        "/system/xbin/su", "/system/sbin/su", "/vendor/bin/su",
        "/cache/su", "/data/su", "/dev/su", "/system/bin/.ext/su",
        "/system/usr/we-need-root/su", "/system/app/Kinguser.apk",
        "/data/adb/magisk", "/sbin/.magisk", "/cache/.disable_magisk",
        "/dev/.magisk.unblock", "/cache/magisk.log", "/data/adb/magisk.img",
        "/data/adb/magisk.db", "/data/adb/magisk_simple", "/init.magisk.rc",
        "/system/xbin/ku.sud", "/data/adb/ksu", "/data/adb/ksud"
    ]
    
    ROOT_MANAGEMENT_APPS = [
        "com.noshufou.android.su", "com.noshufou.android.su.elite",
        "eu.chainfire.supersu", "com.koushikdutta.superuser",
        "com.thirdparty.superuser", "com.yellowes.su",
        "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license",
        "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro",
        "com.topjohnwu.magisk", "me.weishu.kernelsu",
        "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate",
        "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium",
        "com.formyhm.hideroot", "me.phh.superuser", "eu.chainfire.supersu.pro",
        "com.kingouser.com"
    ]
    
    ROOT_PATTERNS = {
        'file_exists': [
            (r'const-string[^"]*"([^"]+)".*?invoke-.*?Ljava/io/File;->exists\(\)Z', 'root_file_check'),
        ],
        'runtime_exec': [
            (r'const-string[^"]*"([^"]+)".*?invoke-.*?Ljava/lang/Runtime;->exec\(', 'root_exec_check'),
        ],
        'system_property': [
            (r'const-string[^"]*"([^"]+)".*?invoke-.*?SystemProperties;->get\(', 'root_property_check'),
        ],
        'package_manager': [
            (r'const-string[^"]*"([^"]+)".*?invoke-.*?PackageManager;->getPackageInfo\(', 'root_app_check'),
        ],
        'process_builder': [
            (r'const-string[^"]*"([^"]+)".*?invoke-.*?ProcessBuilder;->', 'root_process_builder'),
        ],
        'buffered_reader': [
            (r'const-string[^"]*"([^"]+)".*?invoke-.*?BufferedReader;->readLine', 'root_file_read'),
        ],
        'test_keys': [
            (r'const-string[^"]*"(test-keys)"', 'test_keys_check'),
        ],
        'mount_check': [
            (r'const-string[^"]*"(/proc/mounts)"', 'mount_check'),
        ],
        'native_library': [
            (r'const-string[^"]*"([^"]+)".*?System;->loadLibrary', 'native_lib_load'),
        ],
    }
    
    SSL_PATTERNS = {
        'trust_manager': [
            (r'\.method\s+.*?checkServerTrusted\([^)]*\)V', 'ssl_trust_manager'),
            (r'\.method\s+.*?checkClientTrusted\([^)]*\)V', 'ssl_trust_manager_client'),
            (r'\.method\s+.*?getAcceptedIssuers\(\)\[Ljava/security/cert/X509Certificate;', 'ssl_trust_manager_issuers'),
        ],
        'hostname_verifier': [
            (r'\.method\s+.*?verify\(Ljava/lang/String;Ljavax/net/ssl/SSLSession;\)Z', 'ssl_hostname_verifier'),
            (r'\.method\s+.*?verify\(Ljava/lang/String;Ljava/security/cert/X509Certificate;\)Z', 'ssl_hostname_verifier_cert'),
        ],
        'certificate_pinner': [
            (r'\.method\s+.*?check\(Ljava/lang/String;.*?\)V.*?(CertificatePinner|pinning)', 'ssl_cert_pinner'),
            (r'CertificatePinner\$Builder;->add\(', 'ssl_cert_pinner_builder'),
        ],
        'ssl_error_handler': [
            (r'\.method\s+.*?onReceivedSslError\(.*?WebView.*?SslErrorHandler.*?\)V', 'ssl_webview_error'),
        ],
        'okhttp_pinning': [
            (r'okhttp3.*?CertificatePinner', 'okhttp3_pinner'),
            (r'com\.squareup\.okhttp.*?CertificatePinner', 'okhttp_pinner'),
        ],
    }
    
    IGNORE_CLASSES = [
        'androidx.recyclerview', 'androidx.constraintlayout',
        'androidx.coordinatorlayout', 'androidx.appcompat.widget',
        'androidx.core.view', 'androidx.core.widget', 'androidx.fragment',
        'androidx.viewpager', 'androidx.activity.result', 'androidx.emoji',
        'androidx.vectordrawable', 'com.google.android.material',
        'android.widget', 'android.view', 'android.graphics', 'android.animation',
        'kotlinx.coroutines', 'kotlinx.serialization', 'kotlin.collections',
        'kotlin.sequences', 'kotlin.text', 'kotlin.time', 'kotlin.jvm',
        'okio', 'com.google.gson', 'org.json',
        'com.facebook.react', 'com.google.firebase.crashlytics',
        'com.google.android.gms.ads', 'com.google.android.gms.maps',
        'com.google.android.gms.common', 'io.reactivex',
        'com.squareup.picasso', 'com.bumptech.glide',
        'androidx.appcompat.app.AlertController',
        'androidx.core.app.AppLaunchChecker',
        'androidx.startup.StartupLogger',
        'androidx.multidex',
        'timber.log', 'android.util.Log',
        '.ui.', '.view.', '.widget.', '.adapter.', '.fragment.',
        '.activity.', '.dialog.', '.menu.'
    ]
    
    ROOT_METHOD_NAMES = [
        'isRooted', 'isDeviceRooted', 'checkRoot', 'detectRoot', 'checkForRoot',
        'isDeviceCompromised', 'checkSuExists', 'checkForSuBinary', 'checkForBusyBoxBinary',
        'checkForMagiskBinary', 'detectRootManagementApps', 'detectRootCloakingApps',
        'detectTestKeys', 'checkForDangerousProps', 'checkForRWPaths', 'checkForRootNative',
        'checkForMagiskNative', 'canLoadNativeLibrary', 'checkForBinary', 'isRootedWithBusyBoxCheck',
        'isRootedWithoutBusyBoxCheck', 'detectPotentiallyDangerousApps', 'checkSuBinary',
        'findBinary', 'isSuExists', 'isAccessGiven', 'isNativeLibraryLoaded',
        'hasRootPrivileges', 'isRootAvailable', 'isRootAccessGiven', 'isRootGranted',
        'isRootPresent', 'checkRootAccess', 'checkRootFiles', 'checkRootPackages',
        'checkRootProperties', 'checkRootProcesses', 'verifyRootAccess',
        'isDeviceRootedNative', 'checkForRootBinaries', 'checkRootMethod1',
        'checkRootMethod2', 'checkRootMethod3', 'checkRootMethod4', 'checkRootMethod5',
        'isRootedDevice', 'isPhoneRooted', 'isDeviceRootedCheck', 'rootCheck',
        'performRootCheck', 'doRootCheck', 'executeRootCheck', 'runRootCheck',
        'wasNativeLibraryLoaded', 'checkForNativeLibraryReadAccess',
        'mountReader', 'propsReader', 'isAnyPackageFromListInstalled',
        'a', 'b', 'c', 'd', 'e'
    ]
    
    SSL_METHOD_NAMES = [
        'checkServerTrusted', 'verify', 'check', 'onReceivedSslError',
        'checkClientTrusted', 'getAcceptedIssuers', 'validatePinning',
        'checkTrusted', 'checkPinning', 'validateCertificate',
        'validateCertificateChain', 'verifyCertificate', 'verifyHostname',
        'pinCertificate', 'checkCertificateChain', 'checkSSL',
        'validateSSL', 'verifySSL', 'checkCertificate'
    ]
    
    @staticmethod
    def should_ignore_class(class_name: str) -> bool:
        class_lower = class_name.lower()
        
        ui_patterns = ['.ui.', '.view.', '.widget.', '.adapter.', '.fragment.', 
                      '.activity.', '.dialog.', '.menu.', 'textview', 'button',
                      'layout', 'adapter', 'viewholder']
        if any(pattern in class_lower for pattern in ui_patterns):
            return True
            
        for prefix in SmaliPatternMatcher.IGNORE_CLASSES:
            if class_name.startswith(prefix):
                return True
                
        return False
    
    @staticmethod
    def is_likely_security_method(class_name: str, method_name: str, method_body: str) -> bool:
        if method_name in SmaliPatternMatcher.ROOT_METHOD_NAMES:
            return True
        if method_name in SmaliPatternMatcher.SSL_METHOD_NAMES:
            return True
            
        security_keywords = ['root', 'security', 'integrity', 'safety', 'tamper', 
                           'ssl', 'certificate', 'trust', 'pinning', 'detection', 
                           'protect', 'verify', 'check', 'validate', 'rootbeer', 
                           'scottyab', 'uncrackable']
        class_lower = class_name.lower()
        if any(keyword in class_lower for keyword in security_keywords):
            return True
            
        if any(path in method_body for path in SmaliPatternMatcher.COMMON_ROOT_PATHS):
            return True
        if any(app in method_body for app in SmaliPatternMatcher.ROOT_MANAGEMENT_APPS):
            return True
            
        return False

class APKSecurityAnalyzer:
    def __init__(self, apk_path: str, output_name: str = None):
        self.apk_path = Path(apk_path)
        self.output_name = output_name
        self.package_name = None
        self.decompiled_dir = None
        self.detections: List[Detection] = []
        self.method_overloads: Dict[str, List[str]] = {}
        self.detected_root_paths: Set[str] = set()
        self.detected_root_apps: Set[str] = set()
        self.detected_properties: Set[str] = set()
        self.detected_commands: Set[str] = set()
        
        try:
            from androguard.core.bytecodes.apk import APK
            self.apk = APK(str(self.apk_path))
            self.package_name = self.apk.get_package()
        except ImportError:
            console.print("[red][!] Error: androguard==3.3.5 required[/red]")
            console.print("[yellow][!] Run: pip install androguard==3.3.5[/yellow]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red][!] Error loading APK: {e}[/red]")
            sys.exit(1)
    
    def decompile(self) -> bool:
        if shutil.which('apktool') is None:
            console.print("[red][!] Error: apktool not found in PATH[/red]")
            return False
        
        script_dir = Path(__file__).parent
        self.decompiled_dir = script_dir / f"{self.apk_path.stem}_decompiled"
        
        if self.decompiled_dir.exists():
            shutil.rmtree(self.decompiled_dir)
            
        console.print(f"[cyan][*] Decompiling {self.apk_path.name}...[/cyan]")
        
        cmd = ["apktool", "d", "-f", str(self.apk_path), "-o", str(self.decompiled_dir), "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            console.print(f"[red][!] Decompilation failed: {result.stderr}[/red]")
            return False
            
        return True
    
    def collect_method_overloads(self, class_name: str, method_name: str, params: str) -> None:
        key = f"{class_name}.{method_name}"
        if key not in self.method_overloads:
            self.method_overloads[key] = []
        
        param_list = self._parse_method_params(params)
        if param_list not in self.method_overloads[key]:
            self.method_overloads[key].append(param_list)
    
    def _parse_method_params(self, params_str: str) -> str:
        if not params_str:
            return ""
        
        params = []
        i = 0
        while i < len(params_str):
            if params_str[i] == 'L':
                end = params_str.find(';', i)
                if end != -1:
                    obj_type = params_str[i:end+1]
                    java_type = obj_type[1:-1].replace('/', '.')
                    params.append(java_type)
                    i = end + 1
                else:
                    i += 1
            elif params_str[i] == '[':
                array_prefix = '['
                i += 1
                while i < len(params_str) and params_str[i] == '[':
                    array_prefix += '['
                    i += 1
                
                if i < len(params_str):
                    if params_str[i] == 'L':
                        end = params_str.find(';', i)
                        if end != -1:
                            obj_type = params_str[i:end+1]
                            java_type = obj_type[1:-1].replace('/', '.')
                            params.append(f"{array_prefix}{java_type};")
                            i = end + 1
                        else:
                            i += 1
                    else:
                        type_map = {
                            'Z': 'Z', 'B': 'B', 'C': 'C',
                            'S': 'S', 'I': 'I', 'J': 'J',
                            'F': 'F', 'D': 'D'
                        }
                        if params_str[i] in type_map:
                            params.append(f"{array_prefix}{type_map[params_str[i]]}")
                        i += 1
            else:
                type_map = {
                    'Z': 'boolean', 'B': 'byte', 'C': 'char',
                    'S': 'short', 'I': 'int', 'J': 'long',
                    'F': 'float', 'D': 'double', 'V': 'void'
                }
                if params_str[i] in type_map:
                    params.append(type_map[params_str[i]])
                i += 1
        
        return ', '.join(f'"{p}"' for p in params)
    
    def analyze_smali_file(self, smali_path: Path) -> List[Detection]:
        detections = []
        
        try:
            content = smali_path.read_text(encoding='utf-8', errors='ignore')
        except:
            return detections
        
        class_match = re.search(r'\.class\s+(?:public\s+)?(?:final\s+)?(?:abstract\s+)?L([^;]+);', content)
        if not class_match:
            return detections
            
        class_name = class_match.group(1).replace('/', '.')
        
        if SmaliPatternMatcher.should_ignore_class(class_name):
            return detections
        
        methods = re.findall(r'\.method\s+(.+?)\n(.*?)\.end method', content, re.DOTALL)
        
        for method_sig, method_body in methods:
            method_match = re.match(r'(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:final\s+)?(?:native\s+)?(?:synthetic\s+)?(\w+)\(([^)]*)\)(.+)', method_sig)
            if not method_match:
                continue
                
            method_name = method_match.group(1)
            params = method_match.group(2) if method_match.group(2) else ""
            
            if method_name in ['<init>', '<clinit>']:
                continue
                
            self.collect_method_overloads(class_name, method_name, params)
        
        for method_sig, method_body in methods:
            method_match = re.match(r'(?:public\s+|private\s+|protected\s+)?(?:static\s+)?(?:final\s+)?(?:native\s+)?(?:synthetic\s+)?(\w+)\(([^)]*)\)(.+)', method_sig)
            if not method_match:
                continue
                
            method_name = method_match.group(1)
            params = method_match.group(2) if method_match.group(2) else ""
            return_type = method_match.group(3)
            
            if method_name in ['<init>', '<clinit>']:
                continue
            
            if not SmaliPatternMatcher.is_likely_security_method(class_name, method_name, method_body):
                continue
            
            detected_strings = []
            string_matches = re.findall(r'const-string[^"]*"([^"]+)"', method_body)
            detected_strings.extend(string_matches)
            
            for s in detected_strings:
                if s in SmaliPatternMatcher.COMMON_ROOT_PATHS:
                    self.detected_root_paths.add(s)
                elif s in SmaliPatternMatcher.ROOT_MANAGEMENT_APPS:
                    self.detected_root_apps.add(s)
                elif s.startswith('ro.') or s.startswith('service.') or s.startswith('persist.'):
                    self.detected_properties.add(s)
                elif s in ['su', 'busybox', 'magisk', 'mount', 'getprop', 'which', 'id', 'sh']:
                    self.detected_commands.add(s)
            
            if method_name in SmaliPatternMatcher.ROOT_METHOD_NAMES:
                detection = self._create_root_detection_from_method(class_name, method_name, params, return_type)
                if detection:
                    detection.detected_strings = detected_strings
                    key = f"{class_name}.{method_name}"
                    if key in self.method_overloads:
                        detection.overloads = self.method_overloads[key]
                    detections.append(detection)
                    continue
            
            if method_name in SmaliPatternMatcher.SSL_METHOD_NAMES:
                detection = self._create_ssl_detection_from_method(class_name, method_name, params, return_type)
                if detection:
                    detection.detected_strings = detected_strings
                    key = f"{class_name}.{method_name}"
                    if key in self.method_overloads:
                        detection.overloads = self.method_overloads[key]
                    detections.append(detection)
                    continue
            
            if detected_strings:
                for pattern_type, patterns in SmaliPatternMatcher.ROOT_PATTERNS.items():
                    for pattern, tag in patterns:
                        matches = re.findall(pattern, method_body, re.DOTALL | re.MULTILINE)
                        if matches:
                            detection = self._create_root_detection_from_pattern(class_name, method_name, params, return_type, tag)
                            if detection:
                                detection.detected_strings = detected_strings
                                key = f"{class_name}.{method_name}"
                                if key in self.method_overloads:
                                    detection.overloads = self.method_overloads[key]
                                detections.append(detection)
                                break
                
                for pattern_type, patterns in SmaliPatternMatcher.SSL_PATTERNS.items():
                    for pattern, tag in patterns:
                        if re.search(pattern, method_sig + method_body, re.DOTALL | re.MULTILINE):
                            detection = self._create_ssl_detection_from_pattern(class_name, method_name, params, return_type, tag)
                            if detection:
                                detection.detected_strings = detected_strings
                                key = f"{class_name}.{method_name}"
                                if key in self.method_overloads:
                                    detection.overloads = self.method_overloads[key]
                                detections.append(detection)
                                break
        
        return detections
    
    def _create_root_detection_from_method(self, class_name: str, method_name: str, params: str, return_type: str) -> Optional[Detection]:
        bypass_code = 'return false;'
        
        if return_type == 'Z':
            bypass_code = 'return false;'
        elif return_type == 'I':
            bypass_code = 'return 0;'
        elif return_type == 'J':
            bypass_code = 'return 0;'
        elif return_type == 'F':
            bypass_code = 'return 0.0;'
        elif return_type == 'D':
            bypass_code = 'return 0.0;'
        elif 'Ljava/lang/String;' in return_type:
            bypass_code = 'return "";'
        elif '[Ljava/lang/String;' in return_type:
            bypass_code = 'return [];'
        elif 'Ljava/util/List;' in return_type:
            bypass_code = 'return Java.use("java.util.ArrayList").$new();'
        elif 'Ljava/util/Set;' in return_type:
            bypass_code = 'return Java.use("java.util.HashSet").$new();'
        elif 'Ljava/util/Map;' in return_type:
            bypass_code = 'return Java.use("java.util.HashMap").$new();'
        elif return_type == 'V':
            bypass_code = 'return;'
        else:
            bypass_code = 'return null;'
        
        if method_name in ['checkForRoot', 'isRooted', 'isDeviceRooted', 'checkRoot']:
            if return_type == 'V':
                bypass_code = f"""
                try {{
                    this.{method_name}.apply(this, arguments);
                    console.log("[+] Original {method_name} called");
                }} catch(e) {{
                    console.log("[-] Error in {method_name}: " + e);
                }}
                return;
                """
            else:
                bypass_code = f"""
                try {{
                    var result = this.{method_name}.apply(this, arguments);
                    console.log("[+] Original {method_name} result: " + result);
                    return false;
                }} catch(e) {{
                    console.log("[-] Error in {method_name}: " + e);
                    return false;
                }}
                """
        
        return Detection(
            class_name=class_name,
            method_name=method_name,
            method_signature=f"{method_name}({params}){return_type}",
            detection_type="root_check",
            bypass_code=bypass_code
        )
    
    def _create_ssl_detection_from_method(self, class_name: str, method_name: str, params: str, return_type: str) -> Optional[Detection]:
        if method_name == 'checkServerTrusted' and return_type == 'V':
            return Detection(
                class_name=class_name,
                method_name=method_name,
                method_signature=f"{method_name}({params}){return_type}",
                detection_type="ssl_trust_manager",
                bypass_code='return;'
            )
        elif method_name == 'checkClientTrusted' and return_type == 'V':
            return Detection(
                class_name=class_name,
                method_name=method_name,
                method_signature=f"{method_name}({params}){return_type}",
                detection_type="ssl_trust_manager_client",
                bypass_code='return;'
            )
        elif method_name == 'getAcceptedIssuers':
            return Detection(
                class_name=class_name,
                method_name=method_name,
                method_signature=f"{method_name}({params}){return_type}",
                detection_type="ssl_trust_manager_issuers",
                bypass_code='return [];'
            )
        elif method_name == 'verify' and return_type == 'Z':
            return Detection(
                class_name=class_name,
                method_name=method_name,
                method_signature=f"{method_name}({params}){return_type}",
                detection_type="ssl_hostname_verifier",
                bypass_code='return true;'
            )
        elif method_name == 'check' and ('CertificatePinner' in class_name or 'pinning' in class_name.lower()) and return_type == 'V':
            return Detection(
                class_name=class_name,
                method_name=method_name,
                method_signature=f"{method_name}({params}){return_type}",
                detection_type="ssl_certificate_pinner",
                bypass_code='return;'
            )
        elif method_name == 'onReceivedSslError' and return_type == 'V':
            return Detection(
                class_name=class_name,
                method_name=method_name,
                method_signature=f"{method_name}({params}){return_type}",
                detection_type="ssl_webview",
                bypass_code='if (arguments[1] && arguments[1].proceed) { arguments[1].proceed(); } return;'
            )
        elif 'pinning' in method_name.lower() or 'certificate' in method_name.lower():
            if return_type == 'V':
                bypass_code = 'return;'
            elif return_type == 'Z':
                bypass_code = 'return true;'
            else:
                bypass_code = 'return null;'
            
            return Detection(
                class_name=class_name,
                method_name=method_name,
                method_signature=f"{method_name}({params}){return_type}",
                detection_type="ssl_generic",
                bypass_code=bypass_code
            )
        return None
    
    def _create_root_detection_from_pattern(self, class_name: str, method_name: str, params: str, return_type: str, tag: str) -> Optional[Detection]:
        bypass_code = 'return false;'
        
        if return_type == 'Z':
            bypass_code = 'return false;'
        elif return_type == 'I' or return_type == 'J':
            bypass_code = 'return 0;'
        elif return_type == 'V':
            bypass_code = 'return;'
        elif 'Ljava/lang/String;' in return_type:
            bypass_code = 'return "";'
        elif '[' in return_type:
            bypass_code = 'return [];'
        elif 'List' in return_type:
            bypass_code = 'return Java.use("java.util.ArrayList").$new();'
        else:
            bypass_code = 'return null;'
        
        return Detection(
            class_name=class_name,
            method_name=method_name,
            method_signature=f"{method_name}({params}){return_type}",
            detection_type=f"root_{tag}",
            bypass_code=bypass_code
        )
    
    def _create_ssl_detection_from_pattern(self, class_name: str, method_name: str, params: str, return_type: str, tag: str) -> Optional[Detection]:
        if 'trust_manager' in tag:
            if return_type == 'V':
                bypass_code = 'return;'
            elif '[' in return_type:
                bypass_code = 'return [];'
            else:
                bypass_code = 'return null;'
        elif 'hostname_verifier' in tag:
            bypass_code = 'return true;'
        elif 'webview' in tag:
            bypass_code = 'if (arguments[1] && arguments[1].proceed) { arguments[1].proceed(); } return;'
        else:
            if return_type == 'V':
                bypass_code = 'return;'
            elif return_type == 'Z':
                bypass_code = 'return true;'
            else:
                bypass_code = 'return null;'
        
        return Detection(
            class_name=class_name,
            method_name=method_name,
            method_signature=f"{method_name}({params}){return_type}",
            detection_type=f"ssl_{tag}",
            bypass_code=bypass_code
        )
    
    def scan_all_smali(self):
        console.print("[cyan][*] Scanning for security implementations...[/cyan]")
        
        smali_files = []
        for smali_dir in self.decompiled_dir.glob('smali*'):
            smali_files.extend(smali_dir.rglob('*.smali'))
        
        total = len(smali_files)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task(f"[green]Analyzing {total} files...", total=total)
            
            for smali_file in smali_files:
                detections = self.analyze_smali_file(smali_file)
                self.detections.extend(detections)
                progress.update(task, advance=1)
        
        console.print(f"[green][*] Scan complete. Found {len(self.detections)} security checks.[/green]")
    
    def generate_frida_script(self) -> str:
        
        class_detections = {}
        for detection in self.detections:
            if detection.class_name not in class_detections:
                class_detections[detection.class_name] = []
            class_detections[detection.class_name].append(detection)
        
        for class_name in class_detections:
            unique = {}
            for det in class_detections[class_name]:
                key = f"{det.method_name}_{det.method_signature}"
                if key not in unique:
                    unique[key] = det
            class_detections[class_name] = list(unique.values())
        
        script = f"""// Auto-generated Frida bypass script for: {self.package_name}
// Generated by: frida-script-gen
// Root detections found: {sum(1 for d in self.detections if 'root' in d.detection_type)}
// SSL detections found: {sum(1 for d in self.detections if 'ssl' in d.detection_type)}

Java.perform(function() {{
    console.log("[*] Starting bypass for {self.package_name}");
    
"""
        
        if self.detected_root_paths:
            script += f"    const detectedPaths = {json.dumps(list(self.detected_root_paths), indent=8)};\n\n"
        
        if self.detected_root_apps:
            script += f"    const detectedApps = {json.dumps(list(self.detected_root_apps), indent=8)};\n\n"
        
        if self.detected_properties:
            script += f"    const detectedProps = {json.dumps(list(self.detected_properties), indent=8)};\n\n"
        
        need_file_hooks = bool(self.detected_root_paths)
        need_exec_hooks = bool(self.detected_commands)
        need_prop_hooks = bool(self.detected_properties)
        need_pm_hooks = bool(self.detected_root_apps)
        
        if need_file_hooks:
            script += """    try {
        var fopen = Module.findExportByName("libc.so", "fopen");
        if (fopen) {
            Interceptor.attach(fopen, {
                onEnter: function(args) {
                    this.path = args[0].readUtf8String();
                },
                onLeave: function(retval) {
                    if (retval.toInt32() != 0 && this.path && detectedPaths.indexOf(this.path) >= 0) {
                        console.log("[+] Bypassed fopen: " + this.path);
                        retval.replace(ptr(0x0));
                    }
                }
            });
        }
    } catch (e) {
        console.log("[-] Native fopen hook error: " + e);
    }
    
"""
        
        if need_file_hooks:
            script += """    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function() {
            var path = this.getAbsolutePath();
            if (detectedPaths.indexOf(path) >= 0) {
                console.log("[+] Bypassed File.exists: " + path);
                return false;
            }
            return this.exists.apply(this, arguments);
        };
    } catch (e) {
        console.log("[-] File.exists hook error: " + e);
    }
    
"""
        
        if need_exec_hooks:
            detected_cmds_str = json.dumps(list(self.detected_commands))
            script += f"""    try {{
        var Runtime = Java.use("java.lang.Runtime");
        var detectedCmds = {detected_cmds_str};
        
        var exec1 = Runtime.exec.overload("java.lang.String");
        exec1.implementation = function(cmd) {{
            if (detectedCmds.some(c => cmd.indexOf(c) >= 0)) {{
                console.log("[+] Bypassed Runtime.exec: " + cmd);
                return exec1.call(this, "echo");
            }}
            return exec1.call(this, cmd);
        }};
    }} catch (e) {{
        console.log("[-] Runtime.exec hook error: " + e);
    }}
    
"""
        
        if need_prop_hooks:
            script += """    try {
        var SystemProperties = Java.use("android.os.SystemProperties");
        var get = SystemProperties.get.overload('java.lang.String');
        get.implementation = function(key) {
            if (detectedProps.indexOf(key) >= 0) {
                console.log("[+] Bypassed SystemProperties.get: " + key);
                if (key == "ro.debuggable") return "0";
                if (key == "ro.secure") return "1";
                if (key == "ro.build.tags") return "release-keys";
                if (key == "ro.build.selinux") return "1";
                return "";
            }
            return get.call(this, key);
        };
    } catch (e) {
        console.log("[-] SystemProperties hook error: " + e);
    }
    
"""
        
        if need_pm_hooks:
            script += """    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        PM.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
            if (detectedApps.indexOf(packageName) >= 0) {
                console.log("[+] Bypassed PackageManager.getPackageInfo: " + packageName);
                throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
            }
            return this.getPackageInfo.call(this, packageName, flags);
        };
    } catch (e) {
        console.log("[-] PackageManager hook error: " + e);
    }
    
"""
        
        if any('ssl' in d.detection_type for d in self.detections):
            script += """    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        var TrustManager = Java.registerClass({
            name: 'com.sensepost.test.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() { return []; }
            }
        });
        
        var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
            console.log("[+] Bypassed SSLContext.init");
            SSLContext_init.call(this, keyManager, [TrustManager.$new()], secureRandom);
        };
    } catch (e) {
        console.log("[-] SSL TrustManager hook error: " + e);
    }
    
"""
        
        for class_name, detections in sorted(class_detections.items()):
            var_name = self._make_var_name(class_name)
            script += f"\n    try {{\n"
            script += f"        var {var_name} = Java.use(\"{class_name}\");\n"
            
            for detection in detections:
                method_parts = self._parse_method_signature(detection.method_signature)
                
                script += f"        \n"
                
                if detection.overloads and len(detection.overloads) > 1:
                    for i, overload_params in enumerate(detection.overloads):
                        script += f"        try {{\n"
                        if overload_params and overload_params != '""':
                            script += f"            {var_name}.{detection.method_name}.overload({overload_params}).implementation = function() {{\n"
                        else:
                            script += f"            {var_name}.{detection.method_name}.overload().implementation = function() {{\n"
                        script += f"                console.log(\"[+] Bypassed: {class_name}.{detection.method_name}()\");\n"
                        script += f"                {detection.bypass_code}\n"
                        script += f"            }};\n"
                        script += f"        }} catch (e) {{\n"
                        script += f"        }}\n"
                else:
                    if method_parts['params']:
                        script += f"        {var_name}.{detection.method_name}.overload({method_parts['params']}).implementation = function() {{\n"
                    else:
                        script += f"        {var_name}.{detection.method_name}.overload().implementation = function() {{\n"
                    
                    script += f"            console.log(\"[+] Bypassed: {class_name}.{detection.method_name}()\");\n"
                    script += f"            {detection.bypass_code}\n"
                    script += f"        }};\n"
            
            script += f"    }} catch(e) {{\n"
            script += f"        console.log(\"[-] Failed to hook {class_name}: \" + e);\n"
            script += f"    }}\n"
        
        script += """\n    console.log("[*] Bypass script loaded successfully");
});
"""
        
        return script
    
    def _make_var_name(self, class_name: str) -> str:
        var_name = class_name.replace('.', '_').replace('$', '_')
        var_name = re.sub(r'[^a-zA-Z0-9_]', '', var_name)
        if var_name and var_name[0].isdigit():
            var_name = 'c_' + var_name
        return var_name or 'UnknownClass'
    
    def _parse_method_signature(self, signature: str) -> Dict[str, str]:
        match = re.match(r'(\w+)\(([^)]*)\)(.+)', signature)
        if not match:
            return {'params': '', 'args': ''}
        
        params_str = match.group(2)
        if not params_str:
            return {'params': '', 'args': ''}
        
        params = self._parse_method_params(params_str)
        
        param_count = params.count('"')
        if param_count > 0:
            param_count = param_count // 2
            args = ', '.join(f'arg{i}' for i in range(param_count))
        else:
            args = ''
        
        return {
            'params': params,
            'args': args
        }
    
    def analyze_and_generate(self, clean: bool = False) -> Tuple[bool, str]:
        
        if not self.decompile():
            return False, "Decompilation failed"
        
        self.scan_all_smali()
        
        if not self.detections:
            return False, "No security detections found"
        
        script = self.generate_frida_script()
        
        script_dir = Path(__file__).parent
        if self.output_name:
            # Remove .js if already present in output name
            output_name = self.output_name
            if output_name.endswith('.js'):
                output_name = output_name[:-3]
            script_path = script_dir / f"{output_name}.js"
        else:
            script_path = script_dir / f"{self.apk_path.stem}_bypass.js"
        
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script)
        
        if clean and self.decompiled_dir and self.decompiled_dir.exists():
            shutil.rmtree(self.decompiled_dir)
        
        # Return just the filename, not the full path
        return True, script_path.name

def main():
    parser = argparse.ArgumentParser(
        description=f'FridaScriptGen v{VERSION}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    
    parser.add_argument('apk_file', nargs='?', help='APK file to analyze')
    parser.add_argument('-o', '--output', dest='output_name', 
                       help='Custom output name for bypass script')
    parser.add_argument('-c', '--clean', action='store_true',
                       help='Remove decompiled files after analysis')
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit')
    
    args = parser.parse_args()
    
    if not args.apk_file:
        console.print("╭────────────────────────────────────────────────╮")
        console.print("│                                                │")
        console.print("│                 FridaScriptGen                 │")
        console.print("│           Frida Script Generator Tool          │")
        console.print("│           [dim]v1.0 by Sandeep Wawdane[/dim]              │")
        console.print("│                                                │")
        console.print("│  Usage: python3 frida-script-gen.py <apk_file> │")
        console.print("│  Options:                                      │")
        console.print("│    -o, --output    Custom output name          │")
        console.print("│    -c, --clean     Remove decompiled files     │")
        console.print("│    -h, --help      Show this help message      │")
        console.print("│                                                │")
        console.print("╰────────────────────────────────────────────────╯")
        sys.exit(1)
        sys.exit(1)
    
    apk_path = args.apk_file
    
    if not Path(apk_path).exists():
        console.print(f"[red][!] Error: APK file not found: {apk_path}[/red]")
        sys.exit(1)
    
    console.print(f"\n[cyan][*] Analyzing: {apk_path}[/cyan]")
    
    analyzer = APKSecurityAnalyzer(apk_path, args.output_name)
    success, result = analyzer.analyze_and_generate(args.clean)
    
    if success:
        table = Table(title="Analysis Results", show_header=True, header_style="bold magenta")
        table.add_column("Detection Type", style="cyan", width=20)
        table.add_column("Count", justify="right", style="green")
        
        root_count = sum(1 for d in analyzer.detections if 'root' in d.detection_type)
        ssl_count = sum(1 for d in analyzer.detections if 'ssl' in d.detection_type)
        
        table.add_row("Root Detections", str(root_count))
        table.add_row("SSL Detections", str(ssl_count))
        table.add_row("Total", str(len(analyzer.detections)))
        
        console.print("\n", table)
        
        # result is already just the filename now
        console.print(f"\n[green][+] Bypass script generated:[/green] {result}")
        console.print(f"\n[yellow][*] Run with:[/yellow] frida -U -f {analyzer.package_name} -l {result}")
    else:
        console.print(f"\n[red][!] Failed: {result}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()