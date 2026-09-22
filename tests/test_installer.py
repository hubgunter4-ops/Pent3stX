import subprocess
import unittest
from unittest.mock import patch

import pentestx


class InstallerTests(unittest.TestCase):
    def test_runtime_packages_are_allowlisted_per_supported_distribution(self):
        self.assertEqual(
            pentestx.runtime_packages("ubuntu"),
            ["coreutils", "python3", "python3-tk", "python3-yaml"],
        )
        self.assertEqual(
            pentestx.runtime_packages("fedora"),
            ["coreutils", "python3", "python3-pyyaml", "python3-tkinter"],
        )

    def test_install_dependencies_dry_run_never_executes_package_manager(self):
        profiles = pentestx.load_profiles()
        with patch.object(pentestx, "detect_distro", return_value="ubuntu"), patch.object(
            pentestx.subprocess, "run", side_effect=AssertionError("package manager was executed")
        ):
            result = pentestx.install_profile_tools(
                profiles,
                None,
                confirm=True,
                dry_run=True,
                distro="ubuntu",
                install_dependencies=True,
            )

        packages = {item["package"] for item in result}
        self.assertTrue({"python3", "python3-tk", "python3-yaml", "coreutils"}.issubset(packages))
        self.assertTrue({"ffuf", "sqlmap", "nmap", "traceroute"}.issubset(packages))
        self.assertTrue(all(item["dry_run"] for item in result))

    def test_installation_requires_confirmation_outside_dry_run(self):
        with self.assertRaisesRegex(ValueError, "--confirm-tool-install"):
            pentestx.install_profile_tools(
                pentestx.load_profiles(),
                None,
                confirm=False,
                dry_run=False,
                distro="ubuntu",
                install_dependencies=True,
            )

    def test_real_installation_runs_only_generated_allowlisted_commands(self):
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with patch.object(pentestx, "detect_distro", return_value="fedora"), patch.object(
            pentestx.subprocess, "run", return_value=completed
        ) as run, patch.object(pentestx.shutil, "which", return_value="/usr/bin/tool"):
            result = pentestx.install_profile_tools(
                pentestx.load_profiles(),
                "ffuf_safe",
                confirm=True,
                dry_run=False,
                distro="fedora",
                install_tools=["nmap"],
            )

        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].args[0][:2], ["sudo", "dnf"])
        self.assertEqual(run.call_args_list[1].args[0][:3], ["sudo", "dnf", "install"])
        self.assertEqual({item["tool"] for item in result}, {"ffuf", "nmap"})


if __name__ == "__main__":
    unittest.main()
