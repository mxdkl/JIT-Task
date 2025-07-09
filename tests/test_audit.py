import pytest
from unittest.mock import patch, mock_open, MagicMock
from src.scanner import audit
import json

def test_parse_audit_results_empty():
    # should return an empty results list for empty input
    result = audit._parse_audit_results({})
    assert '"results": []' in result

def test_parse_audit_results_with_vulnerability():
    # minimal example of a vulnerability structure
    audit_json = {
        "vulnerabilities": {
            "foo": {
                "via": [
                    {
                        "name": "foo",
                        "url": "GHSA-123",
                        "range": ">=1.0.0",
                    }
                ],
                "nodes": ["node_modules/foo"]
            }
        }
    }
    # patch _get_package_version and _create_dependency_graphs
    with patch("src.scanner.audit._get_package_version", return_value="1.2.0"), \
         patch("src.scanner.audit._create_dependency_graphs", return_value=["foo"]):
        result = audit._parse_audit_results(audit_json)
        assert "GHSA-123" in result
        assert "foo" in result

@patch("src.scanner.audit.subprocess.run")
@patch("src.scanner.audit.init")
def test_run_npm_audit(mock_init, mock_run):
    # simulate subprocess returning a JSON string
    mock_run.return_value.stdout = '{"vulnerabilities": {}}'
    result = audit.run_npm_audit()
    assert '"results": []' in result

def test_get_package_version():
    audit.PACKAGE_LOCK.clear()
    audit.PACKAGE_LOCK.update({
        "packages": {
            "node_modules/foo": {"version": "2.0.0"}
        }
    })
    version = audit._get_package_version("node_modules/foo")
    assert version == "2.0.0"

def test_create_dependency_graphs():
    # fake npm list output
    fake_npm_list = {
        "dependencies": {
            "foo": {
                "version": "1.0.0",
                "dependencies": {
                    "bar": {
                        "version": "2.0.0",
                        "dependencies": {
                            "baz": {
                                "version": "3.0.0",
                                "dependencies": {}
                            }
                        }
                    }
                }
            },
            "qux": {
                "version": "4.0.0",
                "dependencies": {
                    "baz": {
                        "version": "2.0.0",
                        "dependencies": {}
                    }
                }
            }
        }
    }

    # Set the global NPM_LIST_TREE directly
    audit.NPM_LIST_TREE = fake_npm_list
    audit.dependency_graph_cache.clear()
    graphs = audit._create_dependency_graphs("baz", "3.0.0")
    assert any("foo -> bar -> baz" in g for g in graphs)