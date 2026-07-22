import os
import csv
import shutil
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Base directories
BASE_DIR = "/data/olawalea/LoanApps"
ANALYSIS_DIR = os.path.join(BASE_DIR, "SensitiveAPIAnalysis")
APKTOOL_PATH = "apktool"  # Ensure apktool is in PATH

# Ensure analysis directory exists
os.makedirs(ANALYSIS_DIR, exist_ok=True)


def extract_package_name(apk_path):
    """
    Extracts the package name from an APK using apktool.
    Returns None if extraction fails.
    """
    temp_folder = apk_path + "_extracted"

    try:
        # Decompile APK using apktool
        subprocess.run([APKTOOL_PATH, "d", "-f", "-o", temp_folder, apk_path], 
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

        # Check if AndroidManifest.xml exists
        manifest_path = os.path.join(temp_folder, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(f"AndroidManifest.xml not found in {temp_folder}")

        # Extract package name from manifest
        with open(manifest_path, "r", encoding="utf-8") as file:
            for line in file:
                if "package=" in line:
                    package_name = line.split("package=\"")[1].split("\"")[0]
                    shutil.rmtree(temp_folder, ignore_errors=True)  # Clean up
                    return package_name

    except Exception as e:
        logging.error(f"Error extracting package from {apk_path}: {e}")

    shutil.rmtree(temp_folder, ignore_errors=True)  # Cleanup failed extractions
    return None


def build_apk_mapping(base_dir):
    """
    Scans all folders in base_dir and builds a mapping of {package_name: apk_path}.
    """
    apk_mapping = {}  # {package_name: (apk_path, country_folder)}

    for country_folder in os.listdir(base_dir):
        folder_path = os.path.join(base_dir, country_folder)

        if not os.path.isdir(folder_path):
            continue  # Skip files, only process folders

        for apk_file in os.listdir(folder_path):
            if apk_file.endswith(".apk"):
                apk_path = os.path.join(folder_path, apk_file)
                package_name = extract_package_name(apk_path)

                if package_name:
                    apk_mapping[package_name] = (apk_path, country_folder)

    logging.info(f"Built APK mapping for {len(apk_mapping)} apps.")
    return apk_mapping


def copy_matching_apps(csv_file, base_dir, analysis_dir, apk_mapping):
    """
    Reads the CSV file and processes each package name strictly in the given order,
    referencing the pre-built APK mapping.
    """
    success_count = 0
    failed_apps = []  # Store names of failed extractions

    with open(csv_file, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        package_data = list(reader)  # Convert CSV to list to maintain strict order

    for row in package_data:  # Process strictly in CSV order
        app_name = row["App Name"]
        package_name = row["Package Name"]
        classification = row["Country/Classification"]

        if package_name in apk_mapping:
            matching_apk, country_folder = apk_mapping[package_name]
            destination_folder = os.path.join(analysis_dir, country_folder)
            os.makedirs(destination_folder, exist_ok=True)

            # Copy the APK
            destination_path = os.path.join(destination_folder, os.path.basename(matching_apk))
            try:
                shutil.copy2(matching_apk, destination_path)
                logging.info(f"Copied {app_name} ({package_name}) to {destination_folder}")
                success_count += 1
            except Exception as e:
                logging.error(f"Failed to copy {app_name} ({package_name}): {e}")
                failed_apps.append(f"{app_name} ({package_name}) - Copy Failed")
        else:
            logging.warning(f"No matching APK found for {app_name} ({package_name})")
            failed_apps.append(f"{app_name} ({package_name}) - No Matching APK")

    # Final Summary Report
    logging.info(f"\n=== Summary Report ===")
    logging.info(f"Total APKs Copied: {success_count}")
    logging.info(f"Total Failed: {len(failed_apps)}")

    # Save failed apps to a report file
    failed_report_path = os.path.join(analysis_dir, "failed_apps_report.txt")
    with open(failed_report_path, "w", encoding="utf-8") as f:
        for failed in failed_apps:
            f.write(failed + "\n")

    logging.info(f"Failed apps list saved to {failed_report_path}")


if __name__ == "__main__":
    CSV_FILE = os.path.join(BASE_DIR, "Results", "violating_loanwatch.csv")

    logging.info("Scanning all folders and extracting package names...")
    apk_mapping = build_apk_mapping(BASE_DIR)

    logging.info("Processing CSV file...")
    copy_matching_apps(CSV_FILE, BASE_DIR, ANALYSIS_DIR, apk_mapping)

