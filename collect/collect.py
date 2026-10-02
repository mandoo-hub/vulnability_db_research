import subprocess
import json
import os
from datetime import datetime

COLLECT_DIR = "/mnt/vuln_db/collect"

def run_cmd(cmd):
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True
    )
    
    
    print("[DEBUG]", cmd)
    print("[DEBUG RETURN CODE]", result.returncode)
    print("[DEBUG STDOUT]", result.stdout)
    print("[DEBUG] STDERR", result.stderr)
    
    return result.stdout.strip()


def get_os_info():
    info = {}

    with open(
        "/etc/os-release",
        "r",
        encoding="utf-8"
    ) as f:
        for line in f:
            if "=" not in line:
                continue

            key, value = line.strip().split("=", 1)
            info[key] = value.strip('"')

    return {
        "os_id": info.get("ID"),
        "os_name": info.get("NAME"),
        "os_version": info.get("VERSOPM"),
        "kernel": run_cmd("uname -r")
    }

def get_process():
    
    processes = []
    
    output = run_cmd("ps -eo pid,user,comm,args --no-headers")
    
    for line in output.splitlines():
        
        parts = line.strip().split(None, 3)
        
        if len(parts) < 3:
            continue
        
        pid = parts[0]
        user = parts[1]
        command = parts[2]
        
        args = (
            parts[3]
            if len(parts) >= 4
            else ""
        )
        
        exe_path = None
        
        try:
            exe_path =os.readlink(f"/proc/{pid}/exe")
            
        except (
            FileNotFoundError,
            PermissionError,
            OSError
        ):
            pass
        
        processes.append({
            "pid" : int(pid),
            "user" : user,
            "process" : command,
            "executable" : exe_path,
            "args" : args
        })
    
    return processes
        

def get_dpkg_package():
    output = run_cmd(
        "dpkg-query -W -f='${package}|${Version}\\n'"
    )

    packages = []

    for line in output.splitlines():
        if "|" not in line:
            continue
        
        name, version = line.split("|", 1)
        
        packages.append({
            "ecosystem": "Debian",
            "name": name,
            "version": version,
            "source" : "dpkg"
        })
    
    return packages

def get_python_packages():
    output = run_cmd(
        "python3 -m pip list --format=json"
    )
    
    if output:
        try:
            packages = json.loads(output)
            
            result = []
            
            for pkg in packages:
                result.append({
                    "name" : pkg["name"],
                    "version" : pkg["version"],
                    "source" : "pip"
                })
            
            return result
                
            
        except (json.JSONDecodeError, KeyError):
            pass
        
    # 2. pip 조회 실패 시 dpkg-query 사용
    output = run_cmd(
        """dpkg-query -W -f='${Package}|${Version}\\n' 'python3-*' 2>/dev/null"""
    )
    
    packages = []
    
    if output:
        for line in output.splitlines():
            if "|" not in line:
                continue
            
            name, version = line.split("|", 1)
            
            packages.append({
                "name" : name,
                "version" : version,
                "source" : "dpkg"
            })
            
    return packages

def get_docker_container():
    output = run_cmd(
        "docker ps --format '{{.ID}}|{{.Image}}|{{.Names}}}'"
    )
    
    containers = []
    
    if output:
        for line in output.splitlines():
            if "|" not in line:
                continue
            
            cid, image, name = line.split("|",2)
            
            containers.append({
                "container_id" : cid,
                "image" : image,
                "name" : name
            })
            
    return containers    

def get_container_dpkg_packages(container_id):
    cmd = (f"docker exec {container_id} "
           "dpkg-query -W -f='${Package}|${Version}\\n'")
    
    output = run_cmd(cmd)
    
    packages = []
    
    for line in output.splitlines():
        if "|" not in line:
            continue
        
        name, version = line.split("|",1)
        
        packages.append({
            "ecosystem" : "Debian",
            "name" : name,
            "version" : version,
            "source" : "docker-dpkg",
            "container_id" : container_id
        })
        
    return packages

def get_container_python_packages(container_id):
    cmd = (f"docker exec {container_id} "
           "python3 -m pip --disable-pip-version-check "
           "list --format=json")
    
    output = run_cmd(cmd)
    
    if not output:
        return []
    
    try:
        packages = json.loads(output)
        
    except json.JSONDecodeError as e:
        
        print("[ERROR] pip JSON parsing failed")
        print("[ERROR]", e)
        print("[RAW]", repr(output))
        
        return []    
            
    result = []
            
    for pkg in packages:
        
        result.append({
            "ecosystem": "PyPI",
            "name" : pkg["name"],
            "version" : pkg["version"],
            "source" : "pip",
            "container_id" : container_id
        })
                
    return result

# print(
#     get_container_python_packages(
#         "12b62"
#     )
# )

def collect_inventory():
    inventory = {
        "os" : get_os_info(),
        "processes" : [],
        "packages" : [],
        "containers" : []
    }
    
    # Process 현황
    inventory["processes"] = (
        get_process()
    )
    
    # OS Packages
    inventory["packages"].extend(
        get_dpkg_package()
    )
    
    # Python packages
    inventory["packages"].extend(
        get_python_packages()
    )
    
    # Docker
    containers = get_docker_container()
    
    for container in containers:
        cid = container["container_id"]
        
        container["packages"] = []
        
        container["packages"].extend(
            get_container_dpkg_packages(cid)
        )
        
        container["packages"].extend(
            get_container_python_packages(cid)
        )
        
        inventory["containers"].append(
            container
        )
        
    return inventory

def save_inventory(inventory):
    
    os.makedirs(
        COLLECT_DIR,
        exist_ok=True
    )
    
    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )
    
    file_path = os.path.join(
        COLLECT_DIR,
        f"inventory_{timestamp}.json"
    )
    
    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as f:
        
        json.dump(
            inventory,
            f,
            indent=4,
            ensure_ascii=False
        )
    
    return file_path

def main():
    
    inventory = collect_inventory()
    
    saved_file = save_inventory(
        inventory
    )
    
    process_output = {
        "processes": inventory[
            "processes"
        ]
    }
    
    print(
        json.dumps(
            process_output,
            indent=4,
            ensure_ascii=False
        )
    )
    
    print(
        f"\n[+] Inventroy saved:"
        f"{saved_file}"
    )
        

if __name__ == "__main__":
    main()