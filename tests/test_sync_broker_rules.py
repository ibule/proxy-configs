import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from scripts.sync_broker_rules import parse_extended, parse_rules, render_surge, sync


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

    def test_extended_keeps_ipv4_cidr_and_rejects_other_surge_syntax(self):
        self.assertEqual(
            parse_extended('# note\nDOMAIN,API.Example.com\nIP-CIDR,10.1.2.0/24,no-resolve\nIP-CIDR,119.91.245.0/23,no-resolve\n'),
            {'DOMAIN,api.example.com', 'IP-CIDR,10.1.2.0/24,no-resolve', 'IP-CIDR,119.91.245.0/23,no-resolve'},
        )
        cases = [
            'DOMAIN-KEYWORD,example',
            'IP-CIDR,10.0.0.0/8',
            'IP-CIDR,10.0.0.0/8,DIRECT',
            'IP-CIDR,10.0.0.0/33,no-resolve',
            'IP-CIDR,10.0.0.0/08,no-resolve',
            'IP-CIDR6,2001:db8::/32,no-resolve',
            'DOMAIN-SUFFIX,example.com,港股APP',
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_extended(text)


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

    def enable_surge(self):
        self.config['surge'] = {
            'name': 'HK-Stocks',
            'output': 'surge/HK-Stocks.list',
            'extended': 'shadowrocket/Futu_Extended.list',
            'description': 'Test Surge rules.',
            'sources': 'shadowrocket/output.list, shadowrocket/Futu_Extended.list',
            'license': 'v2fly MIT (see licenses/); blackmatrix7 GPL-2.0 (see licenses/)',
            'sections': [
                {'title': 'Futu', 'broker': 'Test'},
                {'title': 'Futu_Extended', 'extended': True},
            ],
        }
        self.write_config()

    def write_extended(self, text):
        path = self.root / 'shadowrocket/Futu_Extended.list'
        path.parent.mkdir(exist_ok=True)
        path.write_text(text)

    def test_surge_merges_extended_ips_dedupes_and_stays_idempotent(self):
        self.config['exclude_suffixes'].append('appsflyersdk.com')
        self.enable_surge()
        self.write_extended(
            '# manual ranges\n'
            'DOMAIN-SUFFIX,local.example\n'
            'DOMAIN-SUFFIX,9oju31.launches.appsflyersdk.com\n'
            'IP-CIDR,10.1.2.0/24,no-resolve\n'
            'IP-CIDR,10.1.2.0/24,no-resolve\n'
            'IP-CIDR,10.0.0.0/8,no-resolve\n'
            'DOMAIN,api.extra.example\n'
        )
        upstream = 'core.example\nlocal.example\nnew.example\nshared.example\n9oju31.launches.appsflyersdk.com\n'
        self.assertEqual(self.run_sync(upstream), 0)
        shadowrocket = self.target.read_text()
        self.assertNotIn('appsflyersdk.com', shadowrocket)
        self.assertNotIn('shared.example', shadowrocket)
        surge_path = self.root / 'surge/HK-Stocks.list'
        text = surge_path.read_text()
        self.assertIn('# UPSTREAM LICENSE: v2fly MIT (see licenses/); blackmatrix7 GPL-2.0 (see licenses/)', text)
        self.assertIn('# SOURCES: shadowrocket/output.list, shadowrocket/Futu_Extended.list', text)
        self.assertIn('# --- Futu ---', text)
        self.assertIn('# --- Futu_Extended ---', text)
        self.assertEqual(text.count('DOMAIN-SUFFIX,local.example\n'), 1)
        self.assertEqual(text.count('IP-CIDR,10.1.2.0/24,no-resolve\n'), 1)
        self.assertIn('DOMAIN-SUFFIX,9oju31.launches.appsflyersdk.com\n', text)
        self.assertIn('DOMAIN,api.extra.example\n', text)
        self.assertLess(
            text.index('IP-CIDR,10.0.0.0/8,no-resolve'),
            text.index('IP-CIDR,10.1.2.0/24,no-resolve'),
        )
        self.assertNotIn('shared.example', text)
        self.assertNotIn('DOMAIN-KEYWORD', text)
        self.assertIn('# TOTAL: 7', text)
        stamp = surge_path.stat().st_mtime_ns
        self.assertEqual(self.run_sync(upstream, check=True), 0)
        self.run_sync(upstream)
        self.assertEqual(surge_path.stat().st_mtime_ns, stamp)

    def test_surge_check_and_invalid_extended_do_not_write(self):
        self.enable_surge()
        self.write_extended('DOMAIN-KEYWORD,futu\n')
        old = self.target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'unsupported Surge rule type'):
            self.run_sync('core.example\nnew.example\n')
        self.assertEqual(self.target.read_bytes(), old)
        self.assertFalse((self.root / 'surge/HK-Stocks.list').exists())

        self.write_extended('IP-CIDR,10.0.0.0/8,no-resolve\n')
        self.assertEqual(self.run_sync('core.example\nnew.example\n', check=True), 1)
        self.assertEqual(self.target.read_bytes(), old)
        self.assertFalse((self.root / 'surge/HK-Stocks.list').exists())

    def test_truncated_extended_list_keeps_previous_files(self):
        self.enable_surge()
        self.write_extended(''.join(f'IP-CIDR,10.0.{i}.0/24,no-resolve\n' for i in range(8)) + 'DOMAIN-SUFFIX,extra.example\n')
        self.run_sync('core.example\n')
        surge_path = self.root / 'surge/HK-Stocks.list'
        old_surge = surge_path.read_bytes()
        old_target = self.target.read_bytes()
        self.write_extended('IP-CIDR,10.0.0.0/24,no-resolve\n')
        with self.assertRaisesRegex(ValueError, 'refusing to remove'):
            self.run_sync('core.example\nadded.example\n')
        self.assertEqual(surge_path.read_bytes(), old_surge)
        self.assertEqual(self.target.read_bytes(), old_target)


class RepoSurgeTests(unittest.TestCase):
    def test_hk_stocks_list_matches_shadowrocket_sources(self):
        root = Path(__file__).resolve().parents[1]
        config = json.loads((root / 'rules/brokers.json').read_text(encoding='utf-8'))
        broker_rules = {
            broker['name']: parse_rules((root / broker['output']).read_text(encoding='utf-8'), 'shadowrocket')
            for broker in config['brokers']
        }
        extended_rules = parse_extended((root / config['surge']['extended']).read_text(encoding='utf-8'))
        text, rules = render_surge(config, broker_rules, extended_rules)
        actual = (root / config['surge']['output']).read_text(encoding='utf-8')
        self.assertEqual(actual, text)
        self.assertEqual(len(rules), len(broker_rules['Futu'] | broker_rules['Tiger'] | broker_rules['Longbridge'] | extended_rules))
        for line in actual.splitlines():
            if not line or line.startswith('#'):
                continue
            kind = line.split(',', 1)[0]
            self.assertIn(kind, {'DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR'})
            if kind == 'IP-CIDR':
                self.assertTrue(line.endswith(',no-resolve'))
        self.assertNotIn('DOMAIN-KEYWORD', actual)
        self.assertIn('v2fly MIT', actual)
        self.assertIn('blackmatrix7 GPL-2.0', actual)
        self.assertIn('licenses/', actual)


if __name__ == '__main__':
    unittest.main()
