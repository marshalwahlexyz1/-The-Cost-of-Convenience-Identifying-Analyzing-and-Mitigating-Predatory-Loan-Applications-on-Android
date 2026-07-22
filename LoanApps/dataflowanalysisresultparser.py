import os
import csv
import xml.etree.ElementTree as ET
from collections import defaultdict

# Base directory
base_dir = "/data/olawalea/LoanApps/SensitiveAPIAnalysis/Results"
output_dir = os.path.join(base_dir, "appmethods")

# Full list of source APIs (your provided list)
source_apis = [
    "<android.content.ContentResolver: android.database.Cursor query(android.net.Uri,java.lang.String[],java.lang.String,java.lang.String[])>",
    "<android.media.ExifInterface: java.lang.String getAttribute(java.lang.String)>",
    "<android.provider.ContactsContract$Contacts: android.database.Cursor query(android.content.ContentResolver,java.lang.String[],java.lang.String[])>",
    "<android.provider.ContactsContract$CommonDataKinds$Phone: android.database.Cursor query(android.content.ContentResolver,java.lang.String[],java.lang.String[])>",
    "<android.provider.ContactsContract$CommonDataKinds$Email: android.database.Cursor query(android.content.ContentResolver,java.lang.String[],java.lang.String[])>",
    "<android.provider.MediaStore$Files: android.database.Cursor query(android.content.ContentResolver,java.lang.String[],java.lang.String[])>",
    "<android.provider.MediaStore$Images$Media: android.database.Cursor query(android.content.ContentResolver,java.lang.String[],java.lang.String[])>",
    "<android.provider.MediaStore$Video$Media: android.database.Cursor query(android.content.ContentResolver,java.lang.String[],java.lang.String[])>",
    "<android.provider.MediaStore$Images$Thumbnails: android.database.Cursor query(android.content.ContentResolver,java.lang.String[],java.lang.String[])>",
    "<android.provider.MediaStore$Video$Thumbnails: android.database.Cursor query(android.content.ContentResolver,java.lang.String[],java.lang.String[])>",
    "<android.content.pm.PackageManager: java.util.List getInstalledApplications(int)>",
    "<android.content.pm.PackageManager: java.util.List getInstalledPackages(int)>",
    "<android.content.pm.PackageManager: android.content.pm.PackageInfo getPackageInfo(java.lang.String,int)>",
    "<android.content.pm.PackageManager: android.content.pm.ApplicationInfo getApplicationInfo(java.lang.String,int)>",
    "<android.telephony.TelephonyManager: java.lang.String getLine1Number()>",
    "<android.telephony.TelephonyManager: java.lang.String getSubscriberId()>",
    "<android.telephony.TelephonyManager: java.lang.String getSimSerialNumber()>",
    "<android.location.LocationManager: android.location.Location getLastKnownLocation(java.lang.String)>",
    "<android.location.Location: double getLatitude()>",
    "<android.location.Location: double getLongitude()>",
    "<android.location.LocationManager: android.location.Location getLastKnownLocation(java.lang.String,java.lang.String)>",
    "<android.location.Location: android.os.Bundle getExtras()>",
    "<android.location.Location: float getAccuracy()>",
    "<android.location.Location: float getBearing()>",
    "<android.location.Location: float getSpeed()>",
    "<android.media.MediaRecorder: void setVideoSource(int)>",
    "<android.os.Environment: java.io.File getExternalStorageDirectory()>",
    "<android.os.Environment: java.io.File getExternalStoragePublicDirectory(java.lang.String)>",
    "<android.content.Context: java.io.File getExternalFilesDir(java.lang.String)>",
    "<android.content.Context: java.io.File[] getExternalFilesDirs(java.lang.String)>",
    "<android.provider.MediaStore$Audio: android.net.Uri getContentUri(java.lang.String)>",
    "<android.provider.MediaStore$Images: android.net.Uri getContentUri(java.lang.String)>",
    "<android.provider.MediaStore$Video: android.net.Uri getContentUri(java.lang.String)>",
    "<android.provider.Telephony$Sms: android.net.Uri getContentUri()>",
    "<android.provider.CallLog$Calls: android.net.Uri getContentUri()>",
    "<java.io.FileInputStream: int read(byte[])>"
]

# Initialize data structures
apk_source_presence = defaultdict(lambda: {"country": "", **{api: "No" for api in source_apis}})
source_counts = defaultdict(int)  # Count unique APKs per source

# Create output directory structure
os.makedirs(output_dir, exist_ok=True)

# Parse XML files and generate per-APK TXT files
for subdir in os.listdir(base_dir):
    subdir_path = os.path.join(base_dir, subdir)
    if not os.path.isdir(subdir_path) or subdir in ["flowdroid_errors.log", "flowdroid_leak_summary.csv", "appmethods"]:
        continue
    
    # Create country subdirectory
    country_dir = os.path.join(output_dir, subdir)
    os.makedirs(country_dir, exist_ok=True)
    
    for xml_file in os.listdir(subdir_path):
        if not xml_file.endswith(".xml"):
            continue
        apk_name = xml_file.replace(".xml", "")
        xml_path = os.path.join(subdir_path, xml_file)
        
        apk_source_presence[apk_name]["country"] = subdir
        
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        leaks = []
        seen_sources = set()  # Track unique sources per APK
        for result in root.findall(".//Result"):
            sink = result.find("Sink").get("Statement")
            sink_method = result.find("Sink").get("Method")
            sink_def = result.find("Sink").get("MethodSourceSinkDefinition")
            
            for source in result.findall("Sources/Source"):
                src = source.get("Statement")
                src_method = source.get("Method")
                src_def = source.get("MethodSourceSinkDefinition")
                
                # Mark source presence and count unique occurrences
                if src_def in source_apis:
                    apk_source_presence[apk_name][src_def] = "Yes"
                    if src_def not in seen_sources:
                        source_counts[src_def] += 1
                        seen_sources.add(src_def)
                
                # Extract methods from taint path
                methods = [path.get("Method") for path in source.findall("TaintPath/PathElement")]
                
                leaks.append({
                    "source": src,
                    "source_def": src_def,
                    "sink": sink,
                    "sink_def": sink_def,
                    "methods": methods
                })
        
        # Write individual TXT file for this APK
        txt_file = os.path.join(country_dir, f"{apk_name}.txt")
        with open(txt_file, "w") as f:
            f.write(f"APK: {apk_name} ({subdir})\n")
            for i, leak in enumerate(leaks, 1):
                f.write(f"Leak {i}:\n")
                f.write(f"  Source: {leak['source']} ({leak['source_def']})\n")
                f.write(f"  Sink: {leak['sink']} ({leak['sink_def']})\n")
                f.write("  Methods:\n")
                for method in leak["methods"]:
                    f.write(f"    {method}\n")
                f.write("\n")  # Newline between leaks

# Write CSV
csv_file = os.path.join(base_dir, "source_leak_summary.csv")
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    headers = ["apk_name", "country_classification"] + source_apis
    writer.writerow(headers)
    for apk, data in apk_source_presence.items():
        row = [apk, data["country"]] + [data[api] for api in source_apis]
        writer.writerow(row)

# Write source counts to a separate summary file
summary_file = os.path.join(base_dir, "source_counts.txt")
with open(summary_file, "w") as f:
    f.write("Source API Counts (Unique APKs):\n")
    for api, count in source_counts.items():
        f.write(f"{api}: {count}\n")

print(f"CSV written to {csv_file}")
print(f"Source counts written to {summary_file}")
print(f"TXT files written to {output_dir}/<country_classification>/<apk_name>.txt")
