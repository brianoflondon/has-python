import os
from typer.testing import CliRunner

from has_python.cli.has import app
import pytest
"""
Testing Note: this relies on running Arcange's PKSA server
"""


def test_cli_authentication_known_key():
    runner = CliRunner()
    args = ["v4vapp.dev"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0

@pytest.mark.timeout(61)
@pytest.mark.slow
def test_cli_authentication_unknown_key():
    runner = CliRunner()
    args = ["v4vapp.dev", "--key-type", "memo"]
    result = runner.invoke(app, args)
    assert result.exit_code == os.EX_UNAVAILABLE
