import subprocess
import json


REPO_DIR = "/repo"
PACKAGE_LOCK = {}


def init():
    # load package-lock.json file
    try:
        with open(f"{REPO_DIR}/package-lock.json", 'r') as file:
            global PACKAGE_LOCK
            PACKAGE_LOCK = json.load(file)
    except FileNotFoundError:
        print("package-lock.json not found. Please ensure you are in a valid Node.js project directory.")
        return []

def run_npm_audit() -> list:
    init()
    result = subprocess.run(
        ['npm', 'audit', '--json'],
        capture_output=True,
        text=True,
        cwd=REPO_DIR,
    )
    audit_json = _parse_audit_results(json.loads(result.stdout))
    return audit_json

def _parse_audit_results(audit_json: dict) -> list:
    vulnerabilities = {"results": []}
    
    for name, info in audit_json.get("vulnerabilities", {}).items():
        for vuln in info.get("via", []):
            if isinstance(vuln, str):
                continue
            if vuln.get("name") != name:
                continue
            for node in info.get("nodes", []):
                version = _get_package_version(node)
                res_obj = {
                    "GHSA ID": vuln.get("url").split("/")[-1] if vuln.get("url") else None,
                    "name": name,
                    "version": version,
                    "dependency_graph": " -> ".join(node.split("node_modules/")[1:]) 
                }
                vulnerabilities["results"].append(res_obj)

    pretty_printed_vulnerabilities = json.dumps(vulnerabilities, indent=4)
    return pretty_printed_vulnerabilities

def _get_package_version(node: str) -> str:
    if node in PACKAGE_LOCK.get("packages", {}):
        return PACKAGE_LOCK["packages"][node].get("version", "unknown")

    
if __name__ == "__main__":
    REPO_DIR = input("Repo path: ")
    vulnerabilities = run_npm_audit()
    print(vulnerabilities)

