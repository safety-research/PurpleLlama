"""Quick overlay test script -- run inside an ARVO container."""

import pathlib
import subprocess
import sys

sys.path.insert(0, "/tmp/new-runtime")
from agent.base import BaseAgent


class TestAgent(BaseAgent):
    AGENT_NAME = "test"

    async def run(self):
        pass


agent = TestAgent(case_id=9180, output_dir=pathlib.Path("/output"))
r = subprocess.run(
    ["git", "diff", "--stat"],
    capture_output=True,
    text=True,
    cwd="/src/librawspeed",
)
print("Before:", r.stdout.strip() or "clean")

agent._setup_overlays()
print("Overlay:", agent._use_overlay, agent._overlay_mounted)

# Modify a file on the overlay
with open("/src/librawspeed/src/librawspeed/decoders/ArwDecoder.cpp", "a") as f:
    f.write("// PATCHED BY OVERLAY TEST\n")

r = subprocess.run(
    ["git", "diff", "--stat"],
    capture_output=True,
    text=True,
    cwd="/src/librawspeed",
)
print("After patch:", r.stdout.strip())

# Capture patch diff (this is what was broken before)
agent._generate_patch_diff()
print("Captured patch:", len(agent.result.patch_content), "bytes")

# Instant revert
agent._reset_overlays()
r = subprocess.run(
    ["git", "diff", "--stat"],
    capture_output=True,
    text=True,
    cwd="/src/librawspeed",
)
reset_status = r.stdout.strip()
if reset_status:
    print("After reset:", reset_status, "(REVERT ISSUE)")
else:
    print("After reset: clean -- instant revert worked!")

agent._teardown_overlays()
print("ALL OVERLAY TESTS PASSED")
