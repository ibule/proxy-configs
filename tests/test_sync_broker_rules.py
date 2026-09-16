import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts.sync_broker_rules import parse_rules, sync


class ParserTests(unittest.TestCase):
    def test_v2fly_preserves_exact_match_and_ignores_attributes(self):
        self.assertEqual(
            parse_rules('# comment\nExample.com @cn\ndomain:example.com\nfull:api.example.com # API\n', 'v2fly'),
            {'DOMAIN-SUFFIX,example.com', 'DOMAIN,api.example.com'},
        )

    def test_rejects_invalid_or_unsupported_upstream_content(self):
        cases = [
            ('<html>error</html>', 'v2fly'),
            ('include:other', 'v2fly'),
            ('regexp:.*', 'v2fly'),
            ('example.com unexpected', 'v2fly'),
            ('DOMAIN-SUFFIX,example.com,DIRECT', 'shadowrocket'),
            ('IP-CIDR,1.2.3.4/32,no-resolve', 'shadowrocket'),
            ('DOMAIN-SUFFIX,*.example.com', 'shadowrocket'),
            ('DOMAIN-SUFFIX,com', 'shadowrocket'),
        ]
        for text, format_name in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_rules(text, format_name)


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'rules').mkdir()
        self.broker = {
            'name': 'Test', 'url': 'https://example.com/upstream',
            'format': 'v2fly', 'license': 'MIT', 'local': 'rules/local.list',
            'output': 'output.list', 'min_rules': 1,
            'required': ['DOMAIN-SUFFIX,core.example'],
        }
        self.config = {'exclude_suffixes': ['shared.example'], 'brokers': [self.broker]}
        self.write_config()
        (self.root / 'rules/local.list').write_text('DOMAIN-SUFFIX,local.example\n')
        self.target = self.root / 'output.list'
        self.target.write_text('DOMAIN-SUFFIX,core.example\nDOMAIN-SUFFIX,local.example\n')

    def write_config(self):
        (self.root / 'rules/brokers.json').write_text(json.dumps(self.config))

    def run_sync(self, text='core.example\n', check=False, loader=None):
        with contextlib.redirect_stdout(io.StringIO()):
            return sync(self.root, check, loader or (lambda url: text))

    def test_merge_exclusions_and_idempotence(self):
        upstream = 'core.example\nlocal.example\nnew.example\nshared.example\napi.shared.example\n'
        self.assertEqual(self.run_sync(upstream), 0)
        result = self.target.read_text()
        self.assertIn('DOMAIN-SUFFIX,new.example\n', result)
        self.assertEqual(result.count('DOMAIN-SUFFIX,local.example\n'), 1)
        self.assertNotIn('shared.example', result)
        stamp = self.target.stat().st_mtime_ns
        self.assertEqual(self.run_sync(upstream, check=True), 0)
        self.run_sync(upstream)
        self.assertEqual(self.target.stat().st_mtime_ns, stamp)

    def test_check_reports_changes_without_writing(self):
        old = self.target.read_bytes()
        self.assertEqual(self.run_sync('core.example\nnew.example', check=True), 1)
        self.assertEqual(self.target.read_bytes(), old)

    def test_empty_missing_core_and_truncated_sources_keep_previous_file(self):
        old = self.target.read_bytes()
        for text in ['', '# comment only', 'other.example']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.run_sync(text)
            self.assertEqual(self.target.read_bytes(), old)
        self.target.write_text(''.join(f'DOMAIN-SUFFIX,old{i}.example\n' for i in range(8)))
        old = self.target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'refusing to remove'):
            self.run_sync()
        self.assertEqual(self.target.read_bytes(), old)

    def test_normal_upstream_deletion_is_not_pinned(self):
        self.run_sync('core.example\none.example\ntwo.example\nobsolete.example')
        self.run_sync('core.example\none.example\ntwo.example')
        result = self.target.read_text()
        self.assertNotIn('obsolete.example', result)
        self.assertIn('DOMAIN-SUFFIX,local.example\n', result)

    def test_second_source_failure_does_not_partially_update_first(self):
        second = dict(self.broker, name='Second', url='https://example.com/second', output='second.list')
        self.config['brokers'].append(second)
        self.write_config()
        old = self.target.read_bytes()

        def loader(url):
            if url == second['url']:
                raise OSError('download failed')
            return 'core.example\nnew.example\n'

        with self.assertRaises(OSError):
            self.run_sync(loader=loader)
        self.assertEqual(self.target.read_bytes(), old)
        self.assertFalse((self.root / 'second.list').exists())

    def test_excluding_core_domain_fails(self):
        self.config['exclude_suffixes'].append('core.example')
        self.write_config()
        with self.assertRaisesRegex(ValueError, 'exclusions removed core'):
            self.run_sync()


if __name__ == '__main__':
    unittest.main()
