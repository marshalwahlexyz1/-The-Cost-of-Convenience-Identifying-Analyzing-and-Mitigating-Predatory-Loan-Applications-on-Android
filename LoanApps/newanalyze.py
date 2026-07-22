import os
import csv
import zipfile
import tempfile
import shutil
from androguard.core.apk import APK

# Android permission list
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

# Country-specific permission restrictions
COUNTRY_SETS = {
    'Indonesia': set(),
    'Kenya': {
        'android.permission.READ_CONTACTS',
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

SUPERSET_PERMS = set(PERMISSIONS)

def extract_xapk(xapk_path, extract_to=None):
    """Extracts main APK from XAPK package with cleanup"""
    temp_dir = extract_to or tempfile.mkdtemp(prefix="xapk_")
    try:
        with zipfile.ZipFile(xapk_path, 'r') as z:
            # Find all APKs and select the main one
            apk_files = [f for f in z.namelist() if f.lower().endswith('.apk')]
            if not apk_files:
                return None

            # Priority: base.apk > largest APK
            base_apk = next((f for f in apk_files if 'base.apk' in f.lower()), None)
            target_file = base_apk or max(apk_files, key=lambda f: z.getinfo(f).file_size)
            
            # Extract and return path
            z.extract(target_file, temp_dir)
            return os.path.join(temp_dir, target_file)
            
    except Exception as e:
        print(f"XAPK extraction failed: {str(e)}")
        return None
    finally:
        if not extract_to and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def analyze_apk(file_path):
    """Analyzes APK/XAPK file with comprehensive error handling"""
    temp_dir = None
    try:
        original_path = file_path
        
        # Handle XAPK files
        if file_path.lower().endswith('.xapk'):
            temp_dir = tempfile.mkdtemp()
            file_path = extract_xapk(file_path, temp_dir)
            if not file_path or not os.path.exists(file_path):
                return None, "XAPK extraction failed"

        # Validate and parse APK
        apk = APK(file_path)
        if not apk.is_valid_APK():
            return None, "Invalid APK structure"
        
        return {
            'package': apk.get_package(),
            'app_name': apk.get_app_name(),
            'permissions': set(apk.get_permissions()),
            'path': original_path
        }, None
        
    except Exception as e:
        return None, f"Analysis error: {str(e)}"
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

def get_country_classification(path):
    """Extracts country and status from directory path"""
    dir_name = os.path.basename(path).lower()
    for country in COUNTRY_SETS:
        if country.lower() in dir_name:
            status = ('Approved' if 'approved' in dir_name else 
                     'Delisted' if 'delisted' in dir_name else 
                     'Unknown')
            return country, status
    return 'Unknown', 'Unknown'

def generate_report(analysis):
    """Generates CSV report entry from analysis results"""
    country, status = get_country_classification(os.path.dirname(analysis['path']))
    perms = analysis['permissions']
    country_perms = COUNTRY_SETS.get(country, set())
    
    return {
        'App Name': analysis['app_name'] or 'Unknown',
        'Package Name': analysis['package'] or 'Unknown',
        'Country/Classification': f"{country}/{status}",
        'Permissions': ', '.join(perms),
        **{p: 'Yes' if p in perms else 'No' for p in PERMISSIONS},
        'Has Restricted Permission': 'TRUE' if perms & country_perms else 'FALSE',
        'ViolateGoogle': 'TRUE' if perms & GOOGLE_PERMS else 'FALSE',
        'ViolateLoanWatch': 'TRUE' if perms & SUPERSET_PERMS else 'FALSE',
        'ViolateCountryPolicy': 'TRUE' if (country_perms and perms & country_perms) else 'FALSE'
    }

def main():
    base_path = "/data/olawalea/LoanApps"
    headers = [
        'App Name', 'Package Name', 'Country/Classification', 'Permissions',
        *PERMISSIONS,
        'Has Restricted Permission',
        'ViolateGoogle', 'ViolateLoanWatch', 'ViolateCountryPolicy'
    ]
    
    folder_stats = {}

    with open('newpermission_report.csv', 'w', newline='', encoding='utf-8') as f_report, \
         open('newprocessing_summary.csv', 'w', newline='', encoding='utf-8') as f_summary:

        report_writer = csv.DictWriter(f_report, fieldnames=headers)
        summary_writer = csv.DictWriter(f_summary, fieldnames=[
            'Folder', 'Total', 'Processed', 'Failed', 'Failed Files'
        ])
        
        report_writer.writeheader()
        summary_writer.writeheader()

        for root, dirs, files in os.walk(base_path):
            valid_files = [f for f in files if f.lower().endswith(('.apk', '.xapk'))]
            if not valid_files:
                continue

            folder_stats[root] = {
                'total': len(valid_files),
                'processed': 0,
                'failed': 0,
                'failed_files': []
            }

            print(f"\nProcessing: {root}")
            print(f"Found {len(valid_files)} APK/XAPK files")

            for idx, file in enumerate(valid_files, 1):
                file_path = os.path.join(root, file)
                result, error = analyze_apk(file_path)
                
                if result:
                    report_writer.writerow(generate_report(result))
                    folder_stats[root]['processed'] += 1
                    print(f"  [{idx}/{len(valid_files)}] Processed: {file}")
                else:
                    folder_stats[root]['failed'] += 1
                    folder_stats[root]['failed_files'].append(file)
                    print(f"  [{idx}/{len(valid_files)}] Failed: {file} - {error}")

            # Write folder summary
            summary_writer.writerow({
                'Folder': root,
                'Total': folder_stats[root]['total'],
                'Processed': folder_stats[root]['processed'],
                'Failed': folder_stats[root]['failed'],
                'Failed Files': '; '.join(folder_stats[root]['failed_files'])
            })

    # Print final summary
    print("\nFinal Processing Summary:")
    print(f"{'Folder':<60} | {'Total':>6} | {'Processed':>8} | {'Failed':>6}")
    print("-" * 93)
    total_stats = {'total': 0, 'processed': 0, 'failed': 0}
    for folder, stats in folder_stats.items():
        print(f"{folder:<60} | {stats['total']:>6} | {stats['processed']:>8} | {stats['failed']:>6}")
        total_stats['total'] += stats['total']
        total_stats['processed'] += stats['processed']
        total_stats['failed'] += stats['failed']
    
    print("-" * 93)
    print(f"{'TOTAL':<60} | {total_stats['total']:>6} | {total_stats['processed']:>8} | {total_stats['failed']:>6}")

if __name__ == '__main__':
    main()
