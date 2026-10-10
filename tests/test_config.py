"""`.exhibita.yml` parsing, defaults, and route resolution."""

from exhibita.config import ExhibitaConfig, RouteHint
from exhibita.models import Finding, Severity


def finding(rule_id="exhibita-sql-injection"):
    return Finding(tool="semgrep", rule_id=rule_id, file="app.py", line=1, severity=Severity.CRITICAL)


def test_missing_config_gives_safe_defaults(tmp_path):
    cfg = ExhibitaConfig.load(tmp_path)
    assert cfg.scanners is None
    assert cfg.gate_severity == Severity.CRITICAL
    assert cfg.lang == "en"
    assert cfg.fix_check is True
    assert cfg.routes == []
    assert cfg.source is None


def test_parses_full_config(tmp_path):
    (tmp_path / ".exhibita.yml").write_text(
        "scanners: [semgrep, gitleaks]\n"
        "ignore: ['tests/*', 'vendor/*']\n"
        "gate_severity: high\n"
        "lang: te\n"
        "fix_check: false\n"
        "verify:\n"
        "  routes:\n"
        "    - match: sql_injection\n"
        "      path: /api/v2/items\n"
        "      param: q\n",
        encoding="utf-8",
    )
    cfg = ExhibitaConfig.load(tmp_path)
    assert cfg.scanners == ["semgrep", "gitleaks"]
    assert cfg.ignore == ["tests/*", "vendor/*"]
    assert cfg.gate_severity == Severity.HIGH
    assert cfg.lang == "te"
    assert cfg.fix_check is False
    assert cfg.routes[0] == RouteHint(match="sql_injection", path="/api/v2/items", param="q")
    assert cfg.source is not None


def test_route_for_matches_class_or_rule_id(tmp_path):
    cfg = ExhibitaConfig(routes=[
        RouteHint(match="sql_injection", path="/a", param="q"),
        RouteHint(match="exhibita-xxe", path="/xml", param=None),
    ])
    assert cfg.route_for(finding(), "sql_injection").path == "/a"
    assert cfg.route_for(finding("exhibita-xxe"), "xxe").path == "/xml"
    assert cfg.route_for(finding("other"), "none") is None


def test_malformed_config_falls_back(tmp_path):
    (tmp_path / ".exhibita.yml").write_text("just a string, not a map\n", encoding="utf-8")
    assert ExhibitaConfig.load(tmp_path).scanners is None


def test_bad_gate_severity_defaults_to_critical(tmp_path):
    (tmp_path / ".exhibita.yml").write_text("gate_severity: bogus\n", encoding="utf-8")
    assert ExhibitaConfig.load(tmp_path).gate_severity == Severity.CRITICAL
