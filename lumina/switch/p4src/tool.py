from __future__ import print_function
import sys, os, time, subprocess

envir_path       = "/home/zhuolong/mysde/bf-sde-9.4.0/"
p4_build         = envir_path + "p4_build.sh"
run_tofino_model = envir_path + "run_tofino_model.sh"
run_switchd      = envir_path + "run_switchd.sh"
set_sde          = envir_path + "set_sde.bash"
run_p4_tests     = envir_path + "run_p4_tests.sh"

target_mode = "hw"

def exe_cmd(cmd):
    subprocess.call(cmd, shell=True)

def compile(file_name):
    exe_cmd("%s %s" % (p4_build, file_name))

def start_switch(p4_name):
    print(  "%s -p %s" % (run_switchd, p4_name))
    exe_cmd("%s -p %s" % (run_switchd, p4_name))

def start_controller(p4_name, config_filepath):
    cmd = "PYTHON_VER=`python --version 2>&1 | awk {'print $2'} | awk -F\".\" {'print $1\".\"$2'}`"
    cmd = cmd + "; export PYTHONPATH=$SDE_INSTALL/lib/python$PYTHON_VER/site-packages/p4testutils:$SDE_INSTALL/lib/python$PYTHON_VER/site-packages/$tofinopd/:$SDE_INSTALL/lib/python$PYTHON_VER/site-packages/tofino:$SDE_INSTALL/lib/python$PYTHON_VER/site-packages/:$PYTHONPATH"
    cmd = cmd + "; python ../controller/controller.py -n %s -f %s" % (p4_name, config_filepath)

    print(cmd)
    exe_cmd(cmd)

def stop_switch():
    exe_cmd("ps -ef | grep tofino | grep -v grep | " \
        "awk '{print $2}' | xargs sudo kill -9")

def print_usage(prog_name):
    print("Usage")
    print("  python %s compile [file_path_to_p4_prog] (e.g., python %s compile ./helloworld.p4)" % (prog_name, prog_name))
    print("  python %s start_switch [p4_prog_name] (e.g., python %s start_switch helloworld)" % (prog_name, prog_name))
    print("  python %s stop_switch" % prog_name)
    print("  python %s start_controller [p4_prog_name] [switch_config_file_path] (e.g., python %s start_controller helloworld ../controller/switch_config.yml)" % (prog_name, prog_name))
    return

if __name__ == "__main__":
    if len(sys.argv) <= 1:
        print_usage(sys.argv[0])
        sys.exit()

    if sys.argv[1] == "compile":
        if (len(sys.argv) <= 2):
            print_usage(sys.argv[0])
        else:
            compile(sys.argv[2])
    elif sys.argv[1] == "start_switch":
        if (len(sys.argv) <= 2):
            print_usage(sys.argv[0])
        else:
            start_switch(sys.argv[2])
    elif sys.argv[1] == "stop_switch":
        stop_switch()
    elif sys.argv[1] == "start_controller":
        if (len(sys.argv) == 3):
            start_controller(sys.argv[2], "../controller/config.yml")
        elif (len(sys.argv) == 4):
            start_controller(sys.argv[2], sys.argv[3])
        else:
            print_usage(sys.argv[0])
    else:
        print_usage(sys.argv[0])
