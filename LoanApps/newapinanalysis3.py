import os
import csv
import json
import logging
import time
import gc
import traceback
from datetime import datetime
from androguard.misc import AnalyzeAPK

# Configuration
BASE_DIR = "/data/olawalea/LoanApps/SensitiveAPIAnalysis"
CSV_FILE = "/data/olawalea/LoanApps/Results/violating_loanwatch.csv"
OUTPUT_CSV = "/data/olawalea/LoanApps/Results/newapianalysisresults3.csv"
PROGRESS_FILE = "/data/olawalea/LoanApps/Results/newanalysisprogress3.json"
PACKAGE_MAPPING_FILE = "/data/olawalea/LoanApps/Results/package_mappings.json"

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("newapkanalysis.log"),
        logging.StreamHandler()
    ]
)

PERMISSION_API_MAPPING = {
    "android.permission.INTERNET": [
        "Lokhttp3/", "Lretrofit2/", "Ljava/net/HttpURLConnection;",
        "Landroid/net/http/", "Lorg/apache/http/", "Lcom/lzy/okgo/",
        "Ljava/net/URL;", "Landroid/webkit/WebView;", "Ljava/net/Socket;",
        "Ljavax/net/", "Lcom/squareup/okhttp/"
    ],
    "android.permission.ACCESS_FINE_LOCATION": [
        "Landroid/location/LocationManager;->getLastKnownLocation",
        "Landroid/location/LocationManager;->requestLocationUpdates",
        "Landroid/location/FusedLocationProviderClient;->getLastLocation"
    ],
    "android.permission.QUERY_ALL_PACKAGES": [
        "Landroid/content/pm/PackageManager;->getInstalledPackages",
        "Landroid/content/pm/PackageManager;->getInstalledApplications"
    ],
    "android.permission.READ_CALL_LOG": ["Landroid/provider/CallLog$Calls;->CONTENT_URI"],
    "android.permission.READ_CONTACTS": [
        "Landroid/provider/ContactsContract;",
        "Landroid/content/ContentResolver;->query"
    ],
    "android.permission.READ_EXTERNAL_STORAGE": [
        "Landroid/os/Environment;->getExternalStorageDirectory",
        "Landroid/os/Environment;->getExternalStorageState",
        "Ljava/io/FileInputStream;->read", "Ljava/io/FileInputStream;->skip",
        "Ljava/io/File;->listFiles", "Ljava/io/File;->createNewFile",
        "Ljava/io/File;->exists"
    ],
    "android.permission.READ_MEDIA_AUDIO": ["Landroid/provider/MediaStore$Audio;"],
    "android.permission.READ_MEDIA_IMAGES": ["Landroid/provider/MediaStore$Images;"],
    "android.permission.READ_MEDIA_VIDEO": ["Landroid/provider/MediaStore$Video;"],
    "android.permission.READ_PHONE_NUMBERS": ["Landroid/telephony/TelephonyManager;->getLine1Number"],
    "android.permission.READ_SMS": [
        "Landroid/provider/Telephony$Sms;",
        "Landroid/content/ContentResolver;->query"
    ],
    "android.permission.WRITE_EXTERNAL_STORAGE": [
        "Ljava/io/FileOutputStream;->write",
        "Ljava/io/File;->mkdir", "Ljava/io/File;->mkdirs"
    ]
}

MANUAL_PACKAGE_MAPPING = {
    "KenyaApproved/L-pesa.apk": "com.app.l_pesa",
    "KenyaApproved/Kopakash.apk": "com.kopakash",
    "KenyaApproved/Metaloan.apk": "com.metaloan",
    "KenyaApproved/Kashbean.apk": "com.kashbean",
    "PakistanApproved/com.app.qistbazaar4.apk": "com.app.qistbazaar4",
    "PakistanApproved/com.edufi.parent.apk": "com.edufi.parent",
    "PhilippinesApproved/com.cashstar.mobile.apk": "com.cashstar.mobile",
    "IndonesiaApproved/com.oriente.finmas_2022-11-08.apk": "com.oriente.finmas"
}

class APKAnalyzer:
    def __init__(self):
        self.processed = set()
        self.remaining = []
        self.package_cache = {}
        self.load_state()

    def load_state(self):
        if os.path.exists(PROGRESS_FILE):
            try:
                with open(PROGRESS_FILE) as f:
                    state = json.load(f)
                    self.processed = set(state.get("processed", []))
                    self.remaining = state.get("remaining", [])
            except Exception as e:
                logging.error(f"Error loading progress: {str(e)}")
        
        if os.path.exists(PACKAGE_MAPPING_FILE):
            try:
                with open(PACKAGE_MAPPING_FILE) as f:
                    self.package_cache = json.load(f)
            except Exception:
                self.package_cache = {}

    def save_state(self):
        with open(PROGRESS_FILE, "w") as f:
            json.dump({
                "processed": list(self.processed),
                "remaining": self.remaining
            }, f, indent=2)
        
        with open(PACKAGE_MAPPING_FILE, "w") as f:
            json.dump(self.package_cache, f, indent=2)

    def get_apk_path(self, row):
        try:
            country, classification = row["Country/Classification"].split("/")
            search_dir = os.path.join(BASE_DIR, f"{country}{classification}")
            
            for apk_file in os.listdir(search_dir):
                if apk_file.endswith(".apk"):
                    apk_path = os.path.join(search_dir, apk_file)
                    rel_path = os.path.relpath(apk_path, BASE_DIR).replace("\\", "/")
                    
                    package = MANUAL_PACKAGE_MAPPING.get(rel_path, self.package_cache.get(rel_path))
                    if not package:
                        a, _, _ = AnalyzeAPK(apk_path)
                        package = a.get_package()
                        self.package_cache[rel_path] = package
                        self.save_state()
                    
                    if package == row["Package Name"]:
                        return apk_path
            return None
        except Exception as e:
            logging.error(f"APK search failed: {str(e)}")
            return None

    def analyze_apk(self, apk_path, package_name, row):
        results = {
            "InternetAccessAPI": "NO",
            "SensitiveAPI": "NO",
            "details": {perm: set() for perm in PERMISSION_API_MAPPING}
        }
        
        try:
            a, d, dx = AnalyzeAPK(apk_path)
            internet_found = False
            permissions = a.get_permissions()
            violating_perms = set(row["ViolatingPermissions"].split(", ")) if "ViolatingPermissions" in row else set()

            for method in dx.get_methods():
                class_name = method.class_name
                method_name = method.name
                parent = f"{class_name}->{method_name}"
                m = method.get_method()

                try:
                    if not hasattr(m, 'get_instructions'):
                        continue  # Silently skip external methods

                    for ins in m.get_instructions():
                        if not ins.get_name().startswith("invoke-"):
                            continue

                        callee = ins.get_output()
                        if "->" not in callee:
                            continue

                        called_class, called_method = callee.split("->", 1)
                        called_method = called_method.split("(")[0]
                        full_callee = f"{called_class}->{called_method}"
                        logging.debug(f"Checking callee: {full_callee} in {parent}")

                        # Check Internet APIs
                        if not internet_found:
                            for pattern in PERMISSION_API_MAPPING["android.permission.INTERNET"]:
                                if (pattern.endswith(";") and called_class.startswith(pattern[:-1])) or \
                                   (pattern in full_callee):
                                    internet_found = True
                                    results["InternetAccessAPI"] = "YES"
                                    logging.info(f"Found internet API '{full_callee}' in {os.path.basename(apk_path)}")
                                    break

                        # Check sensitive APIs
                        for perm, apis in PERMISSION_API_MAPPING.items():
                            if perm == "android.permission.INTERNET":
                                continue
                            for api in apis:
                                if (';->' in api and full_callee == api) or \
                                   (not ';->' in api and called_class.startswith(api.rstrip(';'))):
                                    results["details"][perm].add(f"{parent} -> {full_callee}")
                                    results["SensitiveAPI"] = "YES"
                                    logging.info(f"Found '{perm}' API '{full_callee}' called by '{parent}' in {os.path.basename(apk_path)}")

                except Exception as e:
                    if not str(e).startswith("'ExternalMethod' object has no attribute 'get_instructions'"):
                        logging.warning(f"Skipping method due to error: {str(e)}")

            # Manifest fallbacks
            if not internet_found and "android.permission.INTERNET" in permissions:
                results["InternetAccessAPI"] = "YES"
                logging.info(f"Internet permission found in manifest for {os.path.basename(apk_path)}")

            if results["SensitiveAPI"] != "YES":
                for perm in violating_perms:
                    if perm in PERMISSION_API_MAPPING and perm in permissions:
                        results["SensitiveAPI"] = "YES"
                        logging.info(f"No APIs found, but '{perm}' in manifest for {os.path.basename(apk_path)}")
                        break

            return results
        except Exception as e:
            logging.error(f"Analysis failed for {apk_path}: {str(e)}\n{traceback.format_exc()}")
            return None
        finally:
            gc.collect()

    def process_row(self, row):
        apk_path = self.get_apk_path(row)
        if not apk_path:
            logging.warning(f"No APK found for {row['App Name']}")
            return None

        package_name = row["Package Name"]
        analysis = self.analyze_apk(apk_path, package_name, row)  # Pass row explicitly
        if not analysis:
            return None

        output = {
            "App Name": row["App Name"],
            "Package Name": package_name,
            "Country/Classification": row["Country/Classification"],
            "InternetAccessAPI": analysis["InternetAccessAPI"],
            "SensitiveAPI": analysis["SensitiveAPI"]
        }

        for perm in PERMISSION_API_MAPPING:
            output[perm] = "; ".join(sorted(analysis["details"][perm])).replace("\n", " ").replace(",", " ")

        return output

    def run(self):
        fieldnames = ["App Name", "Package Name", "Country/Classification", 
                     "InternetAccessAPI", "SensitiveAPI"] + list(PERMISSION_API_MAPPING.keys())
        
        if not os.path.exists(OUTPUT_CSV):
            with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
                writer.writeheader()

        with open(CSV_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            all_rows = [row for row in reader if row["Package Name"] not in self.processed]

        total = len(all_rows)
        start_time = time.time()

        for idx, row in enumerate(all_rows):
            try:
                logging.info(f"Processing {idx+1}/{total}: {row['App Name']}")
                output = self.process_row(row)
                
                if output:
                    with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
                        writer.writerow(output)
                    
                    self.processed.add(row["Package Name"])
                    self.remaining = all_rows[idx+1:]
                    self.save_state()

                elapsed = time.time() - start_time
                done = idx + 1
                remaining = total - done
                eta = (elapsed / done * remaining) if done > 0 else 0
                print(f"\nProcessed {done}/{total} ({done/total:.1%})")
                print(f"Elapsed: {datetime.utcfromtimestamp(elapsed).strftime('%H:%M:%S')}")
                print(f"ETA: {datetime.utcfromtimestamp(eta).strftime('%H:%M:%S')}")

            except Exception as e:
                logging.error(f"Failed processing {row['App Name']}: {str(e)}\n{traceback.format_exc()}")
            finally:
                gc.collect()

if __name__ == "__main__":
    analyzer = APKAnalyzer()
    analyzer.run()