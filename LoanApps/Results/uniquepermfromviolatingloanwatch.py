import csv

# Path to the CSV file
CSV_FILE = "/data/olawalea/LoanApps/Results/violating_loanwatch.csv"

def get_unique_permissions(csv_file):
    """
    Reads the CSV file and extracts unique permissions from the ViolatingPermissions column.
    """
    unique_permissions = set()

    with open(csv_file, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        
        for row in reader:
            permissions = row["ViolatingPermissions"].strip('"').split(", ")
            unique_permissions.update(permissions)

    return unique_permissions

if __name__ == "__main__":
    permissions = get_unique_permissions(CSV_FILE)
    
    print("Unique Permissions Found:")
    for perm in sorted(permissions):
        print(perm)

