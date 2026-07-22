import os
import csv
import zipfile
import tempfile
import shutil
import xml.etree.ElementTree as ET
from androguard.core.apk import APK
from androguard.core.axml import AXMLPrinter

# Android permission list
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
    'android.permission.READ_SMS',
    'android.permission.MANAGE_ONGOING_CALLS',
    'android.permission.QUERY_ALL_PACKAGES',
    'android.permission.ACCESS_FINE_LOCATION'
]

# Country-specific restrictions
COUNTRY_SETS = {
    'Indonesia': set(),
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

def extract_xapk(xapk_path):
    """Smart XAPK extractor with multiple fallback strategies"""
    try:
        with zipfile.ZipFile(xapk_path, 'r') as z:
            apk_files = [f for f in z.namelist() if f.lower().endswith('.apk')]
            if not apk_files:
                return None

            # Selection priorities
            base_apk = next((f for f in apk_files if 'base.apk' in f.lower()), None)
            main_apk = next((f for f in apk_files if 'main.apk' in f.lower()), None)
            largest_apk = max(apk_files, key=lambda f: z.getinfo(f).file_size, default=None)
            
            target_file = base_apk or main_apk or largest_apk or apk_files[0]
            
            # Extract to temp directory
            temp_dir = tempfile.mkdtemp()
            z.extract(target_file, temp_dir)
            return os.path.join(temp_dir, target_file)
            
    except Exception as e:
        print(f"XAPK extraction failed: {str(e)}")
        return None

def parse_manifest_direct(apk_path):
    """Robust manifest parser using Androguard's AXML tools"""
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            # Find manifest using case-insensitive search
            manifest_entry = next((f for f in z.namelist() if 'androidmanifest.xml' in f.lower()), None)
            if not manifest_entry:
                return None, None, set()

            # Parse binary XML
            axml = AXMLPrinter(z.read(manifest_entry))
            root = ET.fromstring(axml.get_xml())
            
            # Extract package name
            package = root.get('package', 'unknown')
            
            # Extract permissions
            permissions = set()
            for elem in root.iter('uses-permission'):
                name = elem.get('{http://schemas.android.com/apk/res/android}name')
                if name:
                    permissions.add(name)
            
            # Extract app name
            app_name = 'Unknown'
            application = root.find('application')
            if application is not None:
                app_name = application.get('{http://schemas.android.com/apk/res/android}label', 'Unknown')
            
            return package, app_name, permissions
            
    except Exception as e:
        print(f"Direct manifest parsing failed: {str(e)}")
        return None, None, set()

def analyze_apk(file_path):
    """Hybrid analyzer with multiple fallback strategies"""
    temp_path = None
    try:
        original_path = file_path
        
        # Handle XAPK files
        if file_path.lower().endswith('.xapk'):
            extracted = extract_xapk(file_path)
            if not extracted or not os.path.exists(extracted):
                return None, "XAPK extraction failed"
            file_path = extracted
            temp_path = os.path.dirname(file_path)

        # Try standard Androguard parsing first
        try:
            apk = APK(file_path)
            return {
                'package': apk.package,
                'app_name': apk.get_app_name() or 'Unknown',
                'permissions': set(apk.get_permissions()),
                'path': original_path
            }, None
        except Exception as e:
            pass

        # Fallback: Direct manifest parsing
        package, app_name, permissions = parse_manifest_direct(file_path)
        if package and permissions:
            return {
                'package': package,
                'app_name': app_name,
                'permissions': permissions,
                'path': original_path
            }, None

        return None, "All analysis methods failed"

    except Exception as e:
        return None, f"Critical error: {str(e)}"
    finally:
        if temp_path and os.path.exists(temp_path):
            shutil.rmtree(temp_path)

def get_country_classification(path):
    """Country detection with spelling variations"""
    dir_name = os.path.basename(path).lower()
    aliases = {
        'phillipines': 'Philippines',
        'nigerian': 'Nigeria',
        'kenyan': 'Kenya'
    }
    
    for country in COUNTRY_SETS:
        clean_country = country.lower().replace(' ', '')
        if (clean_country in dir_name or
            any(alias in dir_name for alias in aliases if aliases[alias] == country)):
            status = ('Approved' if 'approved' in dir_name else 
                     'Delisted' if 'delisted' in dir_name else 
                     'Unknown')
            return country, status
    return 'Unknown', 'Unknown'

def generate_report(analysis):
    """Report generator with policy checks"""
    country, status = get_country_classification(os.path.dirname(analysis['path']))
    perms = analysis['permissions']
    country_perms = COUNTRY_SETS.get(country, set())
    
    return {
        'App Name': analysis['app_name'],
        'Package Name': analysis['package'],
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

    with open('mynewreport.csv', 'w', newline='', encoding='utf-8') as f_report, \
         open('mynewsummary.csv', 'w', newline='', encoding='utf-8') as f_summary:

        report_writer = csv.DictWriter(f_report, fieldnames=headers)
        summary_writer = csv.DictWriter(f_summary, fieldnames=[
            'Folder', 'Total', 'Processed', 'Failed', 'Failed Files'
        ])
        
        report_writer.writeheader()
        summary_writer.writeheader()

        for root, _, files in os.walk(base_path):
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
                    print(f"  [{idx}/{len(valid_files)}] ✓ {file}")
                else:
                    folder_stats[root]['failed'] += 1
                    folder_stats[root]['failed_files'].append(file)
                    print(f"  [{idx}/{len(valid_files)}] ✗ {file} - {error}")

            # Write folder summary
            summary_writer.writerow({
                'Folder': root,
                'Total': folder_stats[root]['total'],
                'Processed': folder_stats[root]['processed'],
                'Failed': folder_stats[root]['failed'],
                'Failed Files': '; '.join(folder_stats[root]['failed_files'])
            })

    # Final summary
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
