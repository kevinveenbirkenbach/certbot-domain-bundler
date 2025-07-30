import unittest
from unittest.mock import patch, MagicMock
import hashlib
import main as cb

class TestChunkList(unittest.TestCase):
    def test_chunk_list_exact(self):
        self.assertEqual(
            list(cb.chunk_list([1, 2, 3, 4], 2)),
            [[1, 2], [3, 4]]
        )

    def test_chunk_list_remainder(self):
        self.assertEqual(
            list(cb.chunk_list([1, 2, 3, 4, 5], 2)),
            [[1, 2], [3, 4], [5]]
        )

class TestGroupDomains(unittest.TestCase):
    def test_group_no_categories(self):
        domains = ['a.example.com', 'b.test.org', 'c.example.com']
        grouped = cb.group_domains(domains, [])
        self.assertIn('example.com', grouped)
        self.assertIn('test.org', grouped)
        self.assertCountEqual(grouped['example.com'], ['a.example.com', 'c.example.com'])

    def test_group_with_categories(self):
        domains = ['a.foo.com', 'b.bar.com', 'x.foo.com']
        grouped = cb.group_domains(domains, ['foo.com'])
        # foo.com should collect matching domains
        self.assertIn('foo.com', grouped)
        self.assertCountEqual(grouped['foo.com'], ['a.foo.com', 'x.foo.com'])
        # non-matching domains fall back to base grouping by SLD.TLD
        self.assertIn('bar.com', grouped)
        self.assertEqual(grouped['bar.com'], ['b.bar.com'])

class TestGenerateDomainHash(unittest.TestCase):
    def test_hash_consistency(self):
        domains = ['b.com', 'a.com']
        h = cb.generate_domain_hash(domains)
        expected = hashlib.sha256('a.com,b.com'.encode()).hexdigest()[:8]
        self.assertEqual(h, expected)

class TestRequestCert(unittest.TestCase):
    @patch('main.subprocess.run')
    def test_request_cert_webroot(self, mock_run):
        # simulate successful run
        mock_run.return_value = MagicMock(returncode=0)
        cb.request_cert(
            domains=['example.com'],
            cert_name='testname',
            certbot_acme_challenge_method='webroot',
            certbot_credentials_file=None,
            certbot_dns_propagation_seconds=0,
            certbot_email='user@example.com',
            letsencrypt_webroot_path='/tmp',
            mode_test=True
        )
        called = mock_run.call_args[0][0]
        # assertions on generated command
        self.assertIn('--cert-name', called)
        self.assertIn('testname', called)
        self.assertIn('--webroot', called)
        self.assertIn('-w', called)
        self.assertIn('/tmp', called)
        self.assertIn('--test-cert', called)
        self.assertIn('-d', called)
        self.assertIn('example.com', called)

    @patch('main.subprocess.run')
    def test_request_cert_dns(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        cb.request_cert(
            domains=['foo.org', 'bar.org'],
            cert_name='dnsname',
            certbot_acme_challenge_method='cloudflare',
            certbot_credentials_file='/creds.ini',
            certbot_dns_propagation_seconds=42,
            certbot_email='admin@org',
            letsencrypt_webroot_path=None,
            mode_test=False
        )
        called = mock_run.call_args[0][0]
        self.assertIn('--dns-cloudflare', called)
        self.assertIn('--dns-cloudflare-credentials', called)
        self.assertIn('/creds.ini', called)
        self.assertIn('--dns-cloudflare-propagation-seconds', called)
        self.assertIn('42', called)
        # domain flags
        self.assertEqual(called.count('-d'), 2)

class TestBatchCertNames(unittest.TestCase):
    def test_large_domain_set_cert_name(self):
        # single chunk (default chunk-size=0)
        domains = [f"d{i}.example.com" for i in range(333)]
        domains_str = ",".join(domains)
        expected_hash = cb.generate_domain_hash(domains)
        expected_name = f"certbundle-{expected_hash}-00001"
        with patch('main.request_cert') as mock_req:
            test_argv = ['main.py', '--domains', domains_str, '--certbot-email', 'user@example.com']
            with patch('sys.argv', test_argv):
                cb.main()
        self.assertEqual(mock_req.call_count, 1)
        called_kwargs = mock_req.call_args.kwargs
        self.assertEqual(called_kwargs['cert_name'], expected_name)

    def test_four_chunks_cert_names(self):
        # chunk-size=100 -> 4 chunks for 333 domains
        domains = [f"d{i}.example.com" for i in range(333)]
        domains_str = ",".join(domains)
        expected_hash = cb.generate_domain_hash(domains)
        with patch('main.request_cert') as mock_req:
            test_argv = [
                'main.py',
                '--domains', domains_str,
                '--certbot-email', 'user@example.com',
                '--chunk-size', '100'
            ]
            with patch('sys.argv', test_argv):
                cb.main()
        # Should call request_cert 4 times, suffixes 00001..00004
        self.assertEqual(mock_req.call_count, 4)
        suffixes = [str(i).zfill(5) for i in range(1, 5)]
        expected_names = [f"certbundle-{expected_hash}-{s}" for s in suffixes]
        called_names = [call.kwargs['cert_name'] for call in mock_req.call_args_list]
        self.assertListEqual(called_names, expected_names)
        
if __name__ == '__main__':
    unittest.main()