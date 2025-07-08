from scanner import audit

if __name__ == "__main__":
    vulnerabilities = audit.run_npm_audit()
    print(vulnerabilities)

