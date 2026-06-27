"""Tests for LS004: LLM output to shell injection detection."""

from __future__ import annotations

from pathlib import Path

from llm_seclint.rules.python.llm_shell_injection import LlmShellInjectionRule
from tests.conftest import run_rule_on_code


def _rule() -> LlmShellInjectionRule:
    return LlmShellInjectionRule()


class TestLlmShellInjection:
    def test_subprocess_run_shell_true(self) -> None:
        code = 'subprocess.run(llm_output, shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert findings[0].rule_id == "LS004"
        assert "shell=True" in findings[0].message

    def test_subprocess_call(self) -> None:
        code = 'subprocess.call(command_from_llm, shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_os_system(self) -> None:
        code = 'os.system(llm_response)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_os_popen(self) -> None:
        code = 'os.popen(response.content)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_subprocess_popen(self) -> None:
        code = 'subprocess.Popen(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_safe_static_command(self) -> None:
        code = 'subprocess.run("ls -la", shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_argument_list(self) -> None:
        code = 'subprocess.run(["ls", "-la"])'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_os_system_static(self) -> None:
        code = 'os.system("echo hello")'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_non_shell_function(self) -> None:
        code = 'mylib.run(some_variable)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_list_literal_no_shell(self) -> None:
        """subprocess.run(["ls", "-la"]) is the recommended safe pattern."""
        code = 'subprocess.run(["ls", "-la"])'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_list_literal_shell_false(self) -> None:
        """subprocess.run(["ls", "-la"], shell=False) is safe."""
        code = 'subprocess.run(["ls", "-la"], shell=False)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_dynamic_variable_shell_true(self) -> None:
        """subprocess.run(cmd, shell=True) must always trigger."""
        code = 'subprocess.run(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert "shell=True" in findings[0].message

    def test_dynamic_variable_no_shell(self) -> None:
        """subprocess.run(cmd) with a variable should trigger."""
        code = 'subprocess.run(cmd)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_dynamic_variable_shell_false(self) -> None:
        """subprocess.run(cmd, shell=False) with a variable still triggers."""
        code = 'subprocess.run(cmd, shell=False)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_list_literal_shell_true_flags(self) -> None:
        """shell=True with a list literal is misuse and should be flagged."""
        code = 'subprocess.run(["ls", "-la"], shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert "shell=True" in findings[0].message

    def test_list_with_dynamic_arg_is_safe(self) -> None:
        """A dynamic argument to a fixed non-shell program is safe without
        shell=True: the argument is passed literally, so no shell injection."""
        code = 'subprocess.run(["cmd", user_input])'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_list_dynamic_program_is_safe(self) -> None:
        """A dynamic program name in argv form without shell=True is not shell
        injection -- it's the shape the recommended allowlist pattern uses."""
        code = 'subprocess.run([command_name], capture_output=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_list_shell_interpreter_dynamic_arg_flags(self) -> None:
        """["bash", "-c", x] with a dynamic arg is command injection even
        without shell=True, because bash parses the argument as a command."""
        code = 'subprocess.run(["bash", "-c", user_input])'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_list_shell_interpreter_static_is_safe(self) -> None:
        """["bash", "-c", "echo hi"] with only constants is safe."""
        code = 'subprocess.run(["bash", "-c", "echo hi"])'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_list_code_interpreter_dynamic_arg_flags(self) -> None:
        """["python", "-c", x] runs LLM output as code -- must flag even
        without shell=True (regression guard: argv-list narrowing must not
        silently drop interpreter execution)."""
        for prog in ("python", "python3", "node", "perl", "ruby", "php"):
            code = f'subprocess.run(["{prog}", "-c", llm_output])'
            findings = run_rule_on_code(_rule(), code)
            assert len(findings) == 1, prog

    def test_list_interpreter_through_wrapper_flags(self) -> None:
        """["env", "bash", "-c", x] -- a wrapper prefix must not evade the
        interpreter check."""
        code = 'subprocess.run(["env", "bash", "-c", user_input])'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_tuple_argv_static_is_safe(self) -> None:
        """A tuple argv of constants is the same safe pattern as a list."""
        code = 'subprocess.run(("ls", "-la"))'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_tuple_argv_dynamic_arg_is_safe(self) -> None:
        """A dynamic arg to a fixed non-shell program is safe in tuple form too."""
        code = 'subprocess.run(("cmd", user_input))'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_tuple_interpreter_dynamic_arg_flags(self) -> None:
        """Tuple argv invoking an interpreter with a dynamic arg still flags."""
        code = 'subprocess.run(("bash", "-c", user_input))'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1

    def test_list_shell_truthy_int_flags(self) -> None:
        """shell=1 is truthy and enables the shell -- a dynamic arg must flag."""
        code = 'subprocess.run(["ls", user_input], shell=1)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1
        assert "shell=True" in findings[0].message

    def test_safe_check_output_list_literal(self) -> None:
        """subprocess.check_output(["ls"]) is safe."""
        code = 'subprocess.check_output(["ls", "-la"])'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_safe_check_call_list_literal(self) -> None:
        """subprocess.check_call(["ls"]) is safe."""
        code = 'subprocess.check_call(["ls", "-la"])'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 0

    def test_popen_dynamic_shell_true(self) -> None:
        """subprocess.Popen(cmd, shell=True) should trigger."""
        code = 'subprocess.Popen(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code)
        assert len(findings) == 1


class TestCliAndBuildFileSkipping:
    """Ensure subprocess calls in CLI/build/scripts dirs are skipped."""

    def test_skip_cli_directory(self) -> None:
        """subprocess.run in cli/ directory should NOT trigger."""
        code = 'subprocess.run(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), file_path=Path("project/cli/main.py"), code=code)
        assert len(findings) == 0

    def test_skip_tools_directory(self) -> None:
        """subprocess.run in tools/ directory should NOT trigger."""
        code = 'subprocess.run(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code=code, file_path=Path("project/tools/build.py"))
        assert len(findings) == 0

    def test_skip_scripts_directory(self) -> None:
        """subprocess.run in scripts/ directory should NOT trigger."""
        code = 'subprocess.run(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code=code, file_path=Path("project/scripts/deploy.py"))
        assert len(findings) == 0

    def test_skip_setup_py(self) -> None:
        """subprocess.run in setup.py should NOT trigger."""
        code = 'subprocess.run(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code=code, file_path=Path("setup.py"))
        assert len(findings) == 0

    def test_skip_conftest_py(self) -> None:
        """subprocess.run in conftest.py should NOT trigger."""
        code = 'subprocess.run(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code=code, file_path=Path("tests/conftest.py"))
        assert len(findings) == 0

    def test_skip_manage_py(self) -> None:
        """subprocess.run in manage.py should NOT trigger."""
        code = 'subprocess.run(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code=code, file_path=Path("manage.py"))
        assert len(findings) == 0

    def test_production_code_still_triggers(self) -> None:
        """subprocess.run in regular production code should STILL trigger."""
        code = 'subprocess.run(cmd, shell=True)'
        findings = run_rule_on_code(_rule(), code=code, file_path=Path("src/app/executor.py"))
        assert len(findings) == 1
