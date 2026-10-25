"""New device mutation entry points must not bypass the split delivery lock."""

import ast
from pathlib import Path


def test_all_device_mutations_go_through_shared_subscription_policy():
    root = Path(__file__).resolve().parents[2]
    allowed = {'app/external/remnawave_api.py', 'app/services/bs_device_policy.py'}
    violations = []
    for path in (root / 'app').rglob('*.py'):
        if path.relative_to(root).as_posix() in allowed:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in ('remove_device', 'reset_user_devices')
            ):
                violations.append(f'{path.relative_to(root)}:{node.lineno}: {ast.unparse(node.func)}')
    assert not violations, '\n'.join(violations)
