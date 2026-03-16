import os
import sys

def run(cmd):
    ret = os.system(cmd)
    if ret != 0:
        print(f"❌ Failed: {cmd}")
        sys.exit(1)

def download():
    run("pip install gdown -q")
    import gdown

    compliance_id = os.environ.get("GDRIVE_COMPLIANCE_ID")
    gl_toml_id    = os.environ.get("GDRIVE_GITLEAKS_TOML")
    osv_folder_id = os.environ.get("GDRIVE_OSV_FOLDER_ID")

    missing = [k for k, v in {
        "GDRIVE_COMPLIANCE_ID": compliance_id,
        "GDRIVE_GITLEAKS_TOML": gl_toml_id,
        "GDRIVE_OSV_FOLDER_ID": osv_folder_id,
    }.items() if not v]

    if missing:
        print(f"❌ Missing secrets: {missing}")
        sys.exit(1)

    os.makedirs("data/raw",      exist_ok=True)
    os.makedirs("data/osv",      exist_ok=True)

    print("⬇️  Downloading compliance.xlsx...")
    gdown.download(
        f"https://drive.google.com/uc?id={compliance_id}",
        "data/raw/compliance.xlsx",
        quiet=False
    )
    print("⬇️  Downloading gitleaks.toml...")
    gdown.download(f"https://drive.google.com/uc?id={gl_toml_id}",
                   "data/raw/gitleaks.toml", quiet=False)

    import zipfile

    print("⬇️  Downloading osv_data.zip...")
    gdown.download(
        f"https://drive.google.com/uc?id={osv_folder_id}",
        "osv_data.zip",
        quiet=False
    )
    print("📂 Extracting osv_data.zip...")
    os.makedirs("data/osv", exist_ok=True)
    with zipfile.ZipFile("osv_data.zip", "r") as z:
        z.extractall("data/osv")

    # ADD THIS — verify after extract
    files_found = [f for f in os.listdir("data/osv") if f.endswith(".json")]
    print(f"✅ Extracted {len(files_found)} JSON files to data/osv/")

    os.remove("osv_data.zip")
    print("✅ OSV extracted!")


    # Now run conversion scripts (already on GitHub)
    print("🔄 Converting toml → json...")
    run("python scripts/convert_gitleaks.py")

    print("🔄 Converting xlsx → json...")
    run("python scripts/convert_excel.py")

    print("✅ All done — JSONs generated from source files!")

if __name__ == "__main__":
    download()
