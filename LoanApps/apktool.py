import os
import csv
import zipfile
import subprocess
import xml.etree.ElementTree as ET
import tempfile
import shutil

# Android permission strings based on the provided list
PERMISSIONS = [
    'android.permission.READ_CONTACTS',
    'android.permission.READ_CALL_LOG',
    'android.permission.WRITE_CALL_LOG',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
    'android.permission.MANAGE_MEDIA',
    'android.permission.READ_MEDIA_AUDIO',
    'android.permission.READ_MEDIA_IMAGES',
    'android.permission.READ_MEDIA_VIDEO',
    'android.permission.READ_PHONE_NUMBERS',
    'android.permission.READ_PHONE_STATE',
    'android.permission.READ_PRECISE_PHONE_STATE',
    'android.permission.READ_SMS',
    'android.permission.MANAGE_ONGOING_CALLS',
    'android.permission.QUERY_ALL_PACKAGES',
    'android.permission.ACCESS_FINE_LOCATION'
]

# Country-specific prohibited permissions (as per your mapping)
COUNTRY_SETS = {
    'Indonesia': set(),  # No explicit restrictions
    'Kenya': {
        'android.permission.READ_CONTACTS',
        'android.permission.WRITE_CALL_LOG',
        'android.permission.READ_CALL_LOG'
    },
    'Nigeria': {
        'android.permission.READ_CONTACTS',
        'android.permission.READ_CALL_LOG',
        'android.permission.READ_MEDIA_VIDEO',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.MANAGE_EXTERNAL_STORAGE',
        'android.permission.READ_PHONE_NUMBERS',
        'android.permission.READ_MEDIA_AUDIO',
        'android.permission.READ_MEDIA_IMAGES'
    },
    'Pakistan': {
        'android.permission.READ_MEDIA_IMAGES',
        'android.permission.READ_MEDIA_VIDEO',
        'android.permission.MANAGE_EXTERNAL_STORAGE',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.READ_SMS'
    },
    'Philippines': {
        'android.permission.READ_CONTACTS',
        'android.permission.READ_PHONE_NUMBERS',
        'android.permission.READ_PHONE_STATE',
        'android.permission.READ_PRECISE_PHONE_STATE',
        'android.permission.QUERY_ALL_PACKAGES'
    }
}

# Google's prohibited permissions (Based on Play Store policy)
GOOGLE_PERMS = {
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.READ_MEDIA_IMAGES',
    'android.permission.READ_CONTACTS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.READ_PHONE_NUMBERS',
    'android.permission.READ_MEDIA_VIDEO',
    'android.permission.QUERY_ALL_PACKAGES',
    'android.permission.WRITE_EXTERNAL_STORAGE'
}

# Superset: any permission in PERMISSIONS should flag the app
SUPERSET_PERMS = set(PERMISSIONS)

def extract_xapk(xapk_path, extract_to='/tmp/xapk_extract'):
    """Extracts the .apk file from a .xapk package."""
    try:
        with zipfile.ZipFile(xapk_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        for root, _, files in os.walk(extract_to):
            for file in files:
                if file.lower().endswith('.apk'):
                    return os.path.join(root, file)
    except Exception as e:
        print(f"Error extracting {xapk_path}: {e}")
    return None

def find_manifest(directory):
    """Recursively searches for 'AndroidManifest.xml' (case-insensitive) in the given directory."""
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower() == "androidmanifest.xml":
                return os.path.join(root, file)
    return None

def decompile_apk(apk_path):
    """
    Uses APKtool to decompile the APK and returns the path to AndroidManifest.xml.
    A temporary directory is created for decompilation. If the manifest is not found
    at the root, the function searches recursively.
    """
    temp_dir = tempfile.mkdtemp(prefix="apktool_")
    try:
        result = subprocess.run(["apktool", "d", apk_path, "-o", temp_dir, "-f"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"APKtool failed for {apk_path}: {result.stderr}")
            shutil.rmtree(temp_dir)
            return None
        # Try manifest at the root
        manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            # Recursively search for the manifest if not at the root
            manifest_path = find_manifest(temp_dir)
        if manifest_path and os.path.exists(manifest_path):
            return manifest_path, temp_dir
        else:
            print(f"Manifest not found for {apk_path}")
            shutil.rmtree(temp_dir)
            return None
    except Exception as e:
        print(f"Exception during decompilation of {apk_path}: {e}")
        shutil.rmtree(temp_dir)
        return None

def parse_manifest(manifest_path):
    """
    Parses the AndroidManifest.xml file and extracts:
      - Package name (from the root <manifest> tag attribute 'package')
      - All permissions (from <uses-permission> tags)
      - The application label if available (from the <application> tag attribute 'android:label')
    Returns a tuple: (package_name, app_label, permissions_set)
    """
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        package_name = root.attrib.get('package', 'Unknown')
        permissions = set()
        for perm in root.findall('uses-permission'):
            name = perm.attrib.get('{http://schemas.android.com/apk/res/android}name')
            if name:
                permissions.add(name)
        app_tag = root.find('application')
        app_label = app_tag.attrib.get('{http://schemas.android.com/apk/res/android}label', 'Unknown') if app_tag is not None else 'Unknown'
        return package_name, app_label, permissions
    except Exception as e:
        print(f"Error parsing manifest {manifest_path}: {e}")
        return None, None, set()

def get_country_classification(path):
    """Extracts country and classification from directory path."""
    dir_name = os.path.basename(path).lower()
    for country in COUNTRY_SETS.keys():
        if country.lower() in dir_name:
            if 'approved' in dir_name:
                return country, 'Approved'
            elif 'delisted' in dir_name:
                return country, 'Delisted'
    return 'Unknown', 'Unknown'

def analyze_apk_file(file_path):
    """Processes an APK or XAPK file using APKtool to extract permissions and other data."""
    try:
        if file_path.lower().endswith('.xapk'):
            extracted_apk = extract_xapk(file_path)
            if not extracted_apk:
                return None
            file_path = extracted_apk

        decompilation = decompile_apk(file_path)
        if not decompilation:
            return None
        manifest_path, temp_dir = decompilation

        package_name, app_label, apk_perms = parse_manifest(manifest_path)
        shutil.rmtree(temp_dir)  # Clean up temporary directory

        country, classification = get_country_classification(os.path.dirname(file_path))
        has_restricted_permission = any(perm in COUNTRY_SETS.get(country, set()) for perm in apk_perms)
        violates_google = bool(apk_perms & GOOGLE_PERMS)
        violates_superset = bool(apk_perms & SUPERSET_PERMS)

        violates_country_policy = 'FALSE'
        if country in COUNTRY_SETS and COUNTRY_SETS[country]:
            violates_country_policy = 'TRUE' if has_restricted_permission else 'FALSE'

        return {
            'App Name': app_label,
            'Package Name': package_name,
            'Country/Classification': f"{country}/{classification}",
            'Permissions': ', '.join(apk_perms),
            **{perm: 'Yes' if perm in apk_perms else 'No' for perm in PERMISSIONS},
            'Has Restricted Permission': 'TRUE' if has_restricted_permission else 'FALSE',
            **{f'Violate{c}': 'N/A' for c in COUNTRY_SETS.keys()},
            'ViolateGoogle': 'TRUE' if violates_google else 'FALSE',
            'ViolateLoanWatch': 'TRUE' if violates_superset else 'FALSE',
            'ViolateCountryPolicy': violates_country_policy
        }
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None

def main():
    # Set the base path to your server's LoanApps directory
    base_path = "/data/olawalea/LoanApps"
    print(f"Scanning directory: {base_path}")

    headers = [
        'App Name', 'Package Name', 'Country/Classification', 'Permissions',
        *PERMISSIONS,
        'Has Restricted Permission',
        *['Violate' + country for country in COUNTRY_SETS.keys()],
        'ViolateGoogle', 'ViolateLoanWatch', 'ViolateCountryPolicy'
    ]
    
    folder_stats = {}

    with open('permission_report.csv', 'w', newline='', encoding='utf-8') as f_report:
        writer = csv.DictWriter(f_report, fieldnames=headers)
        writer.writeheader()

        for root, _, files in os.walk(base_path):
            valid_files = [file for file in files if file.lower().endswith(('.apk', '.xapk'))]
            if valid_files:
                print(f"Processing folder: {root} - Found {len(valid_files)} valid files.")
                folder_stats[root] = {"total": len(valid_files), "processed": 0, "failed": 0, "failed_files": []}
                for file in valid_files:
                    file_path = os.path.join(root, file)
                    result = analyze_apk_file(file_path)
                    if result:
                        writer.writerow(result)
                        folder_stats[root]["processed"] += 1
                    else:
                        folder_stats[root]["failed"] += 1
                        folder_stats[root]["failed_files"].append(file)

    with open('processing_summary.csv', 'w', newline='', encoding='utf-8') as f_summary:
        summary_headers = ['Folder', 'Total Files', 'Processed', 'Failed', 'Failed Files']
        summary_writer = csv.DictWriter(f_summary, fieldnames=summary_headers)
        summary_writer.writeheader()
        for folder, stats in folder_stats.items():
            summary_writer.writerow({
                'Folder': folder,
                'Total Files': stats["total"],
                'Processed': stats["processed"],
                'Failed': stats["failed"],
                'Failed Files': '; '.join(stats["failed_files"])
            })

    print("Processing Summary by Folder:")
    for folder, stats in folder_stats.items():
        print(f"Folder: {folder}")
        print(f"  Total Files: {stats['total']}")
        print(f"  Processed: {stats['processed']}")
        print(f"  Failed: {stats['failed']}")
        if stats['failed_files']:
            print(f"  Failed Files: {', '.join(stats['failed_files'])}")
        print()

if __name__ == '__main__':
    main()

