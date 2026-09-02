import importlib.util
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch


class _FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)

    async def ainvoke(self, prompt):
        if self.responses:
            return SimpleNamespace(content=self.responses.pop(0))
        return SimpleNamespace(content="<VERDICT>CONTINUE</VERDICT>")


def load_injection_module():
    for name in [
        'models', 'models.llm', 'tools', 'tools.web_exploit_tool',
        'prompts', 'prompts.prompt', 'langchain_core', 'langchain_core.tools',
        'inj_mod_test'
    ]:
        sys.modules.pop(name, None)

    fake_models = types.ModuleType('models')
    fake_models_llm = types.ModuleType('models.llm')
    fake_models_llm.llm = None
    sys.modules['models'] = fake_models
    sys.modules['models.llm'] = fake_models_llm

    fake_tools = types.ModuleType('tools')
    fake_tools_web = types.ModuleType('tools.web_exploit_tool')

    async def _safe_run_remote(*args, **kwargs):
        return ''

    async def CurlHttpRequestTool(*args, **kwargs):
        return ''

    fake_tools_web._safe_run_remote = _safe_run_remote
    fake_tools_web.CurlHttpRequestTool = CurlHttpRequestTool
    sys.modules['tools'] = fake_tools
    sys.modules['tools.web_exploit_tool'] = fake_tools_web

    fake_prompts = types.ModuleType('prompts')
    fake_prompt_mod = types.ModuleType('prompts.prompt')

    class DeepPentestPrompt:
        os_command_analyzer_prompt = 'analyze {goal} {baseline} {probe_results}'
        os_command_generator_prompt = '{{"payload": "127.0.0.1; if [ -f /static/flag_paths.txt ]; then sleep 3; fi", "expectation": "Delay if path exists"}}'

    fake_prompt_mod.DeepPentestPrompt = DeepPentestPrompt
    sys.modules['prompts'] = fake_prompts
    sys.modules['prompts.prompt'] = fake_prompt_mod

    fake_langchain_core = types.ModuleType('langchain_core')
    fake_langchain_core_tools = types.ModuleType('langchain_core.tools')

    def tool(*args, **kwargs):
        def deco(fn):
            return fn
        return deco

    fake_langchain_core_tools.tool = tool
    sys.modules['langchain_core'] = fake_langchain_core
    sys.modules['langchain_core.tools'] = fake_langchain_core_tools

    spec = importlib.util.spec_from_file_location('inj_mod_test', 'tools/injection_tool.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SmartCodeInjectionToolTests(unittest.IsolatedAsyncioTestCase):
    async def test_blind_exfil_success_requires_literal_flag(self):
        inj = load_injection_module()
        self.assertEqual(inj._extract_real_flag_token('FLAG{MOCK-1}'), 'FLAG{MOCK-1}')
        self.assertEqual(inj._extract_real_flag_token('XBEN{MOCK-2}'), 'XBEN{MOCK-2}')
        self.assertEqual(inj._extract_real_flag_token('   '), '')
        self.assertEqual(inj._extract_real_flag_token('no flag here'), '')

    async def test_spaces_from_blind_exfil_do_not_count_as_success(self):
        inj = load_injection_module()
        fake_llm = _FakeLLM([
            'Strategy: blind command injection via time-based side channel.',
            '{"payload": "127.0.0.1; if [ -f /static/flag_paths.txt ]; then sleep 3; fi", "expectation": "Delay if path exists"}',
            '<VERDICT>PATH_CONFIRMED</VERDICT>\n<PATH_CONFIRMED>/static/flag_paths.txt</PATH_CONFIRMED>',
        ])

        async def fake_send(payload, url, method, body, body_type, headers, cookies, label='', baseline=None):
            body_text = '<pre>Host is reachable!</pre>'
            if str(payload) == '127.0.0.1':
                return {'status': 200, 'length': len(body_text), 'duration': 1.0, 'body': body_text}
            if ';sleep 3' in str(payload):
                return {'status': 200, 'length': len(body_text), 'duration': 4.2, 'body': body_text}
            return {'status': 200, 'length': len(body_text), 'duration': 1.0, 'body': body_text}

        async def fake_exfil(*args, **kwargs):
            return ' ' * 40

        with patch.object(inj, '_send_smart_injection', side_effect=fake_send), \
             patch.object(inj, 'llm', fake_llm), \
             patch.object(inj, '_run_os_time_blind_exfiltration', side_effect=fake_exfil):
            result = await inj.OSCommandInjectionTool(
                'http://127.0.0.1:44622/ping',
                'ip_address=INJECTION',
                '127.0.0.1',
                method='POST',
                body_type='form',
                max_attempts=1,
            )

        self.assertNotIn('✅ SUCCESS: Retrieve flag', result)
        self.assertIn('goal not fully achieved', result.lower())

    async def test_reflection_success_without_literal_flag_does_not_stop(self):
        inj = load_injection_module()
        fake_llm = _FakeLLM([
            'Strategy: output-based attempt.',
            '{"payload": "127.0.0.1; id", "expectation": "See uid output"}',
            '<VERDICT>SUCCESS</VERDICT> confirmed injection primitive',
        ])

        async def fake_send(payload, url, method, body, body_type, headers, cookies, label='', baseline=None):
            body_text = '<pre>Host is reachable!</pre>'
            if str(payload) == '127.0.0.1':
                return {'status': 200, 'length': len(body_text), 'duration': 1.0, 'body': body_text}
            if ';echo test' in str(payload):
                return {'status': 200, 'length': 4, 'duration': 1.0, 'body': 'test'}
            return {'status': 200, 'length': len(body_text), 'duration': 1.0, 'body': body_text}

        with patch.object(inj, '_send_smart_injection', side_effect=fake_send), \
             patch.object(inj, 'llm', fake_llm):
            result = await inj.OSCommandInjectionTool(
                'http://127.0.0.1:44622/ping',
                'ip_address=INJECTION',
                '127.0.0.1',
                method='POST',
                body_type='form',
                max_attempts=1,
            )

        self.assertNotIn('✅ SUCCESS: Retrieve flag', result)
        self.assertIn('goal not fully achieved', result.lower())


if __name__ == '__main__':
    unittest.main()
