import os
import csv
import json
import logging
import time
from datetime import datetime
import gc
import traceback

# Configuration
BASE_DIR = "/data/olawalea/LoanApps/SensitiveAPIAnalysis"
CSV_FILE = "/data/olawalea/LoanApps/Results/violating_loanwatch.csv"
OUTPUT_CSV = "/data/olawalea/LoanApps/Results/api_analysis_results.csv"
TIME_CSV = "/data/olawalea/LoanApps/Results/analysis_times.csv"
PACKAGE_MAPPING_FILE = "/data/olawalea/LoanApps/Results/package_mappings.json"
PROGRESS_FILE = "/data/olawalea/LoanApps/Results/analysis_progress.json"

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("apk_analysis.log"),
        logging.StreamHandler()
    ]
)

# Permission-API mapping (order matters for exclusivity)
PERMISSION_API_MAPPING = {
    "android.permission.INTERNET": [
        "Lokhttp3/",
        "Lretrofit2/Retrofit",
        "Ljava/net/HttpURLConnection;->openConnection",
        "Landroid/net/http/AndroidHttpClient;->newInstance",
        "Lorg/apache/http/HttpResponse",
        "Lcom/lzy/okgo/OkGo",
        "Landroid/webkit/WebView;->loadUrl",
        "Ljava/net/URL;->openConnection"
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
        "Ljava/io/FileInputStream;->read",
        "Ljava/io/FileInputStream;->skip",
        "Ljava/io/File;->listFiles",
        "Ljava/io/File;->createNewFile",
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
        "Ljava/io/File;->mkdir",
        "Ljava/io/File;->mkdirs"
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
    def load_progress(self):
        try:
            if os.path.exists(PROGRESS_FILE):
                with open(PROGRESS_FILE, "r") as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Error loading progress: {e}\n{traceback.format_exc()}")
        return {"processed": [], "remaining": []}

    def save_progress(self, processed, remaining):
        try:
            with open(PROGRESS_FILE, "w") as f:
                json.dump({"processed": processed, "remaining": remaining}, f)
        except Exception as e:
            logging.error(f"Error saving progress: {e}\n{traceback.format_exc()}")

    def get_apk_path(self, row):
        try:
            country, classification = row["Country/Classification"].split("/")
            search_dir = os.path.join(BASE_DIR, f"{country}{classification}")
            search_dir = os.path.normpath(search_dir).replace("\\", "/")
            if not os.path.exists(search_dir):
                logging.warning(f"Directory not found: {search_dir}")
                return None
            
            for apk_file in os.listdir(search_dir):
                if apk_file.endswith(".apk"):
                    apk_path = os.path.join(search_dir, apk_file)
                    rel_path = os.path.normpath(
                        os.path.join(f"{country}{classification}", apk_file)
                    ).replace("\\", "/")
                    package = MANUAL_PACKAGE_MAPPING.get(rel_path)
                    if not package:
                        package = self.extract_package_name(apk_path, rel_path)
                    if package == row["Package Name"]:
                        logging.info(f"Found APK: {apk_path} for package {package}")
                        return apk_path
            logging.warning(f"No APK found for package {row['Package Name']} in {search_dir}")
            return None
        except Exception as e:
            logging.error(f"Error in get_apk_path for {row['Package Name']}: {e}\n{traceback.format_exc()}")
            return None

    def extract_package_name(self, apk_path, rel_path):
        cached = self.load_package_mappings()
        if rel_path in cached:
            return cached[rel_path]
        
        try:
            from androguard.misc import AnalyzeAPK
            a, _, _ = AnalyzeAPK(apk_path)
            package = a.get_package()
            cached[rel_path] = package
            self.save_package_mappings(cached)
            return package
        except Exception as e:
            logging.error(f"Package extraction failed for {apk_path}: {e}\n{traceback.format_exc()}")
            return None

    def load_package_mappings(self):
        try:
            if os.path.exists(PACKAGE_MAPPING_FILE):
                with open(PACKAGE_MAPPING_FILE, "r") as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Error loading package mappings: {e}\n{traceback.format_exc()}")
        return {}

    def save_package_mappings(self, mappings):
        try:
            with open(PACKAGE_MAPPING_FILE, "w") as f:
                json.dump(mappings, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving package mappings: {e}\n{traceback.format_exc()}")

    def analyze_apk(self, apk_path, permissions):
        a = d = dx = None
        try:
            from androguard.misc import AnalyzeAPK
            start_time = time.time()
            logging.info(f"Starting analysis for {apk_path}")
            a, d, dx = AnalyzeAPK(apk_path)
            results = {
                "InternetAccessAPI": "NO",
                "SensitiveAPI": "NO",
                "details": {}
            }

            # Track seen APIs to avoid duplication across permissions
            seen_apis = set()

            # Internet API check
            internet_apis = PERMISSION_API_MAPPING["android.permission.INTERNET"]
            internet_found = False
            for method in dx.get_methods():
                try:
                    parent_class = (method.class_name.decode('utf-8', errors='replace') 
                                  if isinstance(method.class_name, bytes) 
                                  else str(method.class_name))
                    parent_method = (method.name.decode('utf-8', errors='replace') 
                                   if isinstance(method.name, bytes) 
                                   else str(method.name))
                    parent_signature = f"{parent_class}->{parent_method}"
                    encoded_method = method.get_method()
                    for instruction in encoded_method.get_instructions():
                        if instruction.get_name().startswith("invoke-"):
                            called_method = instruction.get_output()
                            if "->" in called_method:
                                class_name, method_name = called_method.split("->")
                                method_str = f"{class_name}->{method_name.split('(')[0]}"
                                for api in internet_apis:
                                    if ";->" in api and api == method_str and method_str not in seen_apis:
                                        combined_str = f"{parent_signature} -> {method_str}"
                                        logging.info(f"Found exact internet API '{combined_str}' in {os.path.basename(apk_path)}")
                                        internet_found = True
                                        seen_apis.add(method_str)
                                    elif ";->" not in api and class_name.startswith(api) and method_str not in seen_apis:
                                        combined_str = f"{parent_signature} -> {method_str}"
                                        logging.info(f"Found class-based internet API '{combined_str}' in {os.path.basename(apk_path)}")
                                        internet_found = True
                                        seen_apis.add(method_str)
                                    if internet_found:
                                        break
                        if internet_found:
                            break
                except Exception as e:
                    logging.warning(f"Skipping method due to error: {e}")
                    continue
                if internet_found:
                    break
            if internet_found:
                results["InternetAccessAPI"] = "YES"

            # Sensitive API check
            for perm in permissions:
                if perm not in PERMISSION_API_MAPPING:
                    continue
                
                target_apis = set(PERMISSION_API_MAPPING[perm])
                found = set()
                for method in dx.get_methods():
                    try:
                        parent_class = (method.class_name.decode('utf-8', errors='replace') 
                                      if isinstance(method.class_name, bytes) 
                                      else str(method.class_name))
                        parent_method = (method.name.decode('utf-8', errors='replace') 
                                       if isinstance(method.name, bytes) 
                                       else str(method.name))
                        parent_signature = f"{parent_class}->{parent_method}"
                        encoded_method = method.get_method()
                        for instruction in encoded_method.get_instructions():
                            if instruction.get_name().startswith("invoke-"):
                                called_method = instruction.get_output()
                                if "->" in called_method:
                                    class_name, method_name = called_method.split("->")
                                    method_str = f"{class_name}->{method_name.split('(')[0]}"
                                    if method_str in seen_apis:
                                        continue  # Skip if already assigned to another permission
                                    for api in target_apis:
                                        if ";->" in api and api == method_str:
                                            combined_str = f"{parent_signature} -> {method_str}"
                                            logging.info(f"Found exact API '{combined_str}' for permission '{perm}' in {os.path.basename(apk_path)}")
                                            found.add(combined_str)
                                            seen_apis.add(method_str)
                                        elif ";->" not in api and class_name.startswith(api):
                                            combined_str = f"{parent_signature} -> {method_str}"
                                            logging.info(f"Found class-based API '{combined_str}' for permission '{perm}' in {os.path.basename(apk_path)}")
                                            found.add(combined_str)
                                            seen_apis.add(method_str)
                    except Exception as e:
                        logging.warning(f"Skipping method due to error: {e}")
                        continue
                
                if found:
                    results["details"][perm] = list(found)
                    results["SensitiveAPI"] = "YES"

            analysis_time = time.time() - start_time
            logging.info(f"Analyzed {os.path.basename(apk_path)} in {analysis_time:.1f}s")
            return results, analysis_time
        except Exception as e:
            logging.error(f"Analysis failed for {apk_path}: {e}\n{traceback.format_exc()}")
            return None, 0
        finally:
            if a is not None and d is not None and dx is not None:
                del a, d, dx
            gc.collect()

    def process_row(self, row, processed_set, output_file, time_file):
        logging.info(f"Processing row for {row['App Name']} ({row['Package Name']})")
        apk_path = self.get_apk_path(row)
        if not apk_path:
            logging.warning(f"No APK path found for {row['App Name']}")
            return
        
        try:
            permissions = [p.strip() for p in row["ViolatingPermissions"].split(", ")]
            result, analysis_time = self.analyze_apk(apk_path, permissions)
            if not result:
                logging.warning(f"Analysis returned None for {row['App Name']}")
                return
            
            output = {
                "App Name": row["App Name"],
                "Package Name": row["Package Name"],
                "Country/Classification": row["Country/Classification"],
                "InternetAccessAPI": result["InternetAccessAPI"],
                "SensitiveAPI": result["SensitiveAPI"]
            }
            for perm in PERMISSION_API_MAPPING.keys():
                output[perm] = ""
            
            for perm in result["details"]:
                if perm in PERMISSION_API_MAPPING:
                    output[perm] = "; ".join(result["details"][perm])  # Use semicolon as delimiter
            
            with open(output_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=output.keys())
                if os.stat(output_file).st_size == 0:
                    writer.writeheader()
                writer.writerow(output)
                f.flush()
                os.fsync(f.fileno())
            
            time_output = {
                "Package Name": row["Package Name"],
                "AnalysisTime": f"{analysis_time:.1f}"
            }
            with open(time_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Package Name", "AnalysisTime"])
                if os.stat(time_file).st_size == 0:
                    writer.writeheader()
                writer.writerow(time_output)
                f.flush()
                os.fsync(f.fileno())
            
            processed_set.add(row["Package Name"])
            logging.info(f"Completed processing for {row['App Name']}")
        except Exception as e:
            logging.error(f"Processing failed for {row['App Name']}: {e}\n{traceback.format_exc()}")

    def main(self):
        logging.info("Starting single-threaded analysis")
        progress = self.load_progress()
        processed_pkgs = set(progress["processed"])
        remaining_rows = progress["remaining"]
        
        with open(CSV_FILE, "r") as f:
            reader = csv.DictReader(f)
            all_rows = list(reader)
            logging.info(f"Loaded {len(all_rows)} rows from {CSV_FILE}")
        
        if not remaining_rows:
            remaining_rows = [row for row in all_rows if row["Package Name"] not in processed_pkgs]
        logging.info(f"Processing {len(remaining_rows)} remaining rows")
        
        all_perms = sorted(PERMISSION_API_MAPPING.keys())
        headers = ["App Name", "Package Name", "Country/Classification",
                  "InternetAccessAPI", "SensitiveAPI"] + all_perms
        
        with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
        with open(TIME_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Package Name", "AnalysisTime"])
            writer.writeheader()
        
        processed_set = set(processed_pkgs)
        start_time = time.time()
        total = len(remaining_rows)
        
        for i, row in enumerate(remaining_rows):
            self.process_row(row, processed_set, OUTPUT_CSV, TIME_CSV)
            done = len(processed_set) - len(processed_pkgs)
            elapsed = time.time() - start_time
            remaining = total - done
            
            print(f"\nProcessed {done}/{total} ({done/total:.1%})")
            print(f"Elapsed: {datetime.utcfromtimestamp(elapsed).strftime('%H:%M:%S')}")
            if done > 0:
                eta = elapsed / done * remaining
                print(f"ETA: {datetime.utcfromtimestamp(eta).strftime('%H:%M:%S')}")
        
        final_processed = list(processed_set)
        final_remaining = [row for row in all_rows if row["Package Name"] not in processed_set]
        self.save_progress(final_processed, final_remaining)
        logging.info("Analysis completed")

if __name__ == "__main__":
    analyzer = APKAnalyzer()
    analyzer.main()
