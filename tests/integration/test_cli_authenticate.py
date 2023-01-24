import os

import pytest
from typer.testing import CliRunner

from has_python.cli.has import app

"""
Testing Note: this relies on running Arcange's PKSA server
"""


def test_cli_known_key_authentication():
    runner = CliRunner()
    args = ["v4vapp.dev", "--no-display"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0


@pytest.mark.slow
def test_cli_unknown_key_authentication():
    runner = CliRunner()
    args = ["v4vapp.dev", "--key-type", "memo", "--no-display"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
