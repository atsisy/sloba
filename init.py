import os
import subprocess

path = "linux"
linux_repo = "https://github.com/torvalds/linux.git"

if not os.path.exists(path):
    print("Linux git repository is not exist.")
    subprocess.call("git clone " + linux_repo, shell=True)
else:
    print("Linux git repository is already exist.")

print("Initializing is done.")
