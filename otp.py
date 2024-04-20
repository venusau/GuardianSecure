import subprocess
import re

def get_installed_packages():
    process = subprocess.Popen(['pip', 'list', '--format=freeze'], stdout=subprocess.PIPE)
    output, _ = process.communicate()
    output = output.decode('utf-8')
    installed_packages = output.split('\n')
    return installed_packages

def get_package_size(package_name):
    process = subprocess.Popen(['pip', 'show', package_name], stdout=subprocess.PIPE)
    output, _ = process.communicate()
    output = output.decode('latin-1')  # Decode using 'latin-1' encoding

    # Extract the size from the output
    size_match = re.search(r'^Size: (\d+)', output, re.MULTILINE)
    if size_match:
        size = int(size_match.group(1))
        return size
    else:
        return None


if __name__ == "__main__":
    installed_packages = get_installed_packages()

    for package in installed_packages:
        if package:
            package_name = package.split('==')[0]
            package_size = get_package_size(package_name)
            if package_size is not None:
                print(f"{package_name}: {package_size} bytes")
            else:
                print(f"Could not find size information for package: {package_name}")
