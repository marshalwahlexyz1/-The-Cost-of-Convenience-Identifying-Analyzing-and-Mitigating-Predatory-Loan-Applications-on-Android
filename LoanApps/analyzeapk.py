import os
import csv
import zipfile
from androguard.core.apk import APK

# Android permission strings based on the provided list
PERMISSIONS = [
    'android.permission.READ_CONTACTS',
    'android.permission.READ_CALL_LOG',
    'android.permission.READ_EXTERNAL_STORAGE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.READ_MEDIA_AUDIO',
    'android.permission.READ_MEDIA_IMAGES',
    'android.permission.READ_MEDIA_VIDEO',
    'android.permission.READ_SMS',
    'android.permission.QUERY_ALL_PACKAGES',
    'android.permission.ACCESS_FINE_LOCATION'
]

# Country-specific prohibited permissions (as per your mapping)
COUNTRY_SETS = {
    'Indonesia': set(),  # No explicit restrictions
    'Kenya': {
        'android.permission.READ_CONTACTS',
        'android.permission.READ_CALL_LOG'
    },
    'Nigeria': {
        'android.permission.READ_CONTACTS',
        'android.permission.READ_CALL_LOG',
        'android.permission.READ_MEDIA_VIDEO',
    'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.READ_MEDIA_AUDIO',
        'android.permission.READ_MEDIA_IMAGES'
    },
    'Pakistan': {
        'android.permission.READ_MEDIA_IMAGES',
        'android.permission.READ_MEDIA_VIDEO',
        'android.permission.READ_CONTACTS',
        'android.permission.READ_EXTERNAL_STORAGE',
        'android.permission.READ_SMS'
    },
    'Philippines': {
        'android.permission.READ_CONTACTS'

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

# Superset of all permissions (any permission in PERMISSIONS should flag the app)
SUPERSET_PERMS = set(PERMISSIONS)

def extract_xapk(xapk_path, extract_to='/tmp/xapk_extract'):
    """Extracts the .apk file from a .xapk package."""
    try:
        with zipfile.ZipFile(xapk_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        # Find the .apk file in the extracted contents
        for root, _, files in os.walk(extract_to):
            for file in files:
                if file.lower().endswith('.apk'):
                    return os.path.join(root, file)
    except Exception as e:
        print(f"Error extracting {xapk_path}: {e}")
    return None

def get_country_classification(path):
    """Extract country and classification from directory path."""
    dir_name = os.path.basename(path).lower()  # Normalize casing
    for country in COUNTRY_SETS.keys():
        if country.lower() in dir_name:
            if 'approved' in dir_name:
                return country, 'Approved'
            elif 'delisted' in dir_name:
                return country, 'Delisted'
    return 'Unknown', 'Unknown'

def analyze_apk(apk_path):
    """Analyzes an APK and extracts its permissions."""
    try:
        # Handle .xapk extraction if needed
        if apk_path.endswith('.xapk'):
            extracted_apk = extract_xapk(apk_path)
            if not extracted_apk:
                return None  # Extraction failed
            apk_path = extracted_apk

        apk = APK(apk_path)
        country, classification = get_country_classification(os.path.dirname(apk_path))

        # Get actual permissions from the APK
        apk_perms = set(apk.get_permissions())

        # Determine if any restricted permission exists for the country
        has_restricted_permission = any(perm in COUNTRY_SETS.get(country, set()) for perm in apk_perms)
        violates_google = bool(apk_perms & GOOGLE_PERMS)
        violates_superset = bool(apk_perms & SUPERSET_PERMS)

        violates_country_policy = 'FALSE'
        if country in COUNTRY_SETS and COUNTRY_SETS[country]:
            violates_country_policy = 'TRUE' if has_restricted_permission else 'FALSE'

        return {
            'App Name': apk.get_app_name(),
            'Package Name': apk.get_package(),
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
        print(f"Error processing {apk_path}: {e}")
        return None

def main():
    headers = [
        'App Name', 'Package Name', 'Country/Classification', 'Permissions',
        *PERMISSIONS,
        'Has Restricted Permission',
        *['Violate' + country for country in COUNTRY_SETS.keys()],
        'ViolateGoogle', 'ViolateLoanWatch', 'ViolateCountryPolicy'
    ]
    
    # Dictionary to track processing statistics by folder
    folder_stats = {}

    with open('permission_reporttest.csv', 'w', newline='', encoding='utf-8') as f_report:
        writer = csv.DictWriter(f_report, fieldnames=headers)
        writer.writeheader()

        for root, _, files in os.walk('/data/olawalea/LoanApps'):
            # Filter files ending with .apk or .xapk
            valid_files = [file for file in files if file.lower().endswith(('.apk', '.xapk'))]
            if valid_files:
                folder_stats[root] = {"total": len(valid_files), "processed": 0, "failed": 0, "failed_files": []}
                for file in valid_files:
                    file_path = os.path.join(root, file)
                    result = analyze_apk(file_path)
                    if result:
                        writer.writerow(result)
                        folder_stats[root]["processed"] += 1
                    else:
                        folder_stats[root]["failed"] += 1
                        folder_stats[root]["failed_files"].append(file)

    # Write a summary CSV file with folder statistics.
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

    # Print summary to console.
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

