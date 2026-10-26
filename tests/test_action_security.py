import re
from pathlib import Path


ACTION = Path(__file__).resolve().parents[1] / "action.yml"


def test_run_scripts_do_not_interpolate_untrusted_expressions():
    text = ACTION.read_text()
    block_scripts = re.findall(r"(?m)^      run: \|\n((?:^        [^\n]*\n?)*)", text)
    inline_scripts = re.findall(r"(?m)^      run: (?!\|)(.*)$", text)

    for script in [*block_scripts, *inline_scripts]:
        assert "${{ inputs." not in script
        assert "${{ github.event" not in script
        assert "${{ github.head_ref" not in script
        assert "${{ github.ref_name" not in script