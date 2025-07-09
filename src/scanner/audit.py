import subprocess
import json
import os
from typing import Optional, Dict, List, Any
from nodesemver import satisfies


REPO_DIR = "/repo"

PACKAGE_LOCK = {}
NPM_LIST_TREE = {}

"""
memoization cache
needed becuase each output is uniquly idenitied by (ghsa id, name, version and depenency graph). 
it is impossible to tell if 2 results will be the same without constructing the entire object.
"""
dependency_graph_cache = {}
package_version_cache = {}



def init():
    # load package-lock.json file
    try:
        with open(os.path.join(REPO_DIR, "package-lock.json"), 'r') as file:
            global PACKAGE_LOCK
            PACKAGE_LOCK = json.load(file)
    except FileNotFoundError:
        print("package-lock.json not found. Please ensure you are in a valid Node.js project directory.")
        return []

    # run npm list --all --json
    global NPM_LIST_TREE
    try:
        result = subprocess.run(
            ['npm', 'list', '--all', '--json'],
            capture_output=True,
            text=True,
            cwd=REPO_DIR,
        )
        NPM_LIST_TREE = json.loads(result.stdout)
    except Exception as e:
        print(f"Failed to run npm list: {e}. Make sure you have all packages installed.")
        NPM_LIST_TREE = None


def run_npm_audit() -> Optional[Dict[str, Any]]:
    init()
    result = subprocess.run(
        ['npm', 'audit', '--json'],
        capture_output=True,
        text=True,
        cwd=REPO_DIR,
    )
    audit_json = _parse_audit_results(json.loads(result.stdout))
    return audit_json

def _parse_audit_results(audit_json: dict) -> Optional[Dict[str, Any]]:
    vulnerabilities = {"results": []}

    seen = set()
    for name, info in audit_json.get("vulnerabilities", {}).items():
        for vuln in info.get("via", []):
            if isinstance(vuln, str):
                continue
            if vuln.get("name") != name:
                continue

            ghsa_id = vuln.get("url") 

            for node in info.get("nodes", []):
                version = _get_package_version(node)

                if not satisfies(version, vuln.get("range")):
                    continue
                
                graphs = _create_dependency_graphs(name, version)
                for graph in graphs:
                    result_key = (ghsa_id, name, version, graph)
                    if result_key in seen:
                        continue
                    seen.add(result_key)
                    res_obj = {
                        "GHSA ID": ghsa_id,
                        "name": name,
                        "version": version,
                        "dependency_graph": graph
                    }
                    vulnerabilities["results"].append(res_obj)

    pretty_printed_vulnerabilities = json.dumps(vulnerabilities, indent=4)
    return pretty_printed_vulnerabilities

def _get_package_version(node: str) -> str:
    #memoize
    if node in package_version_cache:
        return package_version_cache[node]
    
    version = PACKAGE_LOCK.get("packages", {}).get(node, {}).get("version", "unknown")
    package_version_cache[node] = version
    return version

def _create_dependency_graphs(name: str, version: str) -> List[str]:
    # memoize
    cache_key = (name, version)
    if cache_key in dependency_graph_cache:
        return dependency_graph_cache[cache_key]

    """
    npm will put indirect project depencencies in node_modules/
    this means that it is not reliable for getting the true dependency graph.
    npm list is used instead
    """
    graphs = []
    results = NPM_LIST_TREE
    if results is None:
        return graphs

    # non recursive tree search
    stack = [(results, [])]
    while stack:
        node, path = stack.pop()
        dependencies = node.get("dependencies", {})
        for dep_name, dep_data in dependencies.items():
            new_path = path + [dep_name]
            if dep_name == name and dep_data.get("version") == version:
                graphs.append(" -> ".join(new_path))
            stack.append((dep_data, new_path))

    dependency_graph_cache[cache_key] = graphs
    return graphs


if __name__ == "__main__":
    REPO_DIR = input("repo dir: ")
    vulnerabilities = run_npm_audit()
    print(vulnerabilities)
