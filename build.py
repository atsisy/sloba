import subprocess

cp_cmd = "cp ./src/slob.c ./linux/mm"
cp_config = "cp ./src/.config ./linux"
cd_linux_cmd = "cd linux"
build_cmd = "make -j$(grep -c processor /proc/cpuinfo)"
back_cd = "cd ../"

subprocess.call(cp_cmd, shell=True)
subprocess.call(cp_config, shell=True)
subprocess.call(cd_linux_cmd + " && " + build_cmd + " && " + back_cd, shell=True)
