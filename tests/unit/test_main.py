import unittest
from unittest.mock import patch, MagicMock, call
import main as cb


class TestBatchCertNames(unittest.TestCase):
    def test_large_domain_set_cert_name(self):
        # single chunk (default chunk-size=0)
        domains = [f"d{i}.example.com" for i in range(333)]
        domains_str = ",".join(domains)
        expected_hash = cb.generate_domain_hash(domains)
        expected_name = f"certbundle-{expected_hash}-00001"
        with patch('main.request_cert') as mock_req:
            mock_req.return_value = {
                "cert_name": expected_name,
                "domains": domains,
                "returncode": 0,
                "status": "updated",
                "reason": "ok"
            }
            test_argv = ['main.py', '--domains', domains_str, '--certbot-email', 'user@example.com']
            with patch('sys.argv', test_argv):
                with self.assertRaises(SystemExit) as cm:
                    cb.main()
        self.assertEqual(mock_req.call_count, 1)
        called_kwargs = mock_req.call_args.kwargs
        self.assertEqual(called_kwargs['cert_name'], expected_name)
        self.assertEqual(cm.exception.code, 0)  # no failures

    def test_four_chunks_cert_names(self):
        # chunk-size=100 -> 4 chunks for 333 domains
        domains = [f"d{i}.example.com" for i in range(333)]
        domains_str = ",".join(domains)
        expected_hash = cb.generate_domain_hash(domains)
        with patch('main.request_cert') as mock_req:
            # Pretend all chunks succeed
            def sequenced(*args, **kwargs):
                return {
                    "cert_name": kwargs['cert_name'],
                    "domains": kwargs['domains'],
                    "returncode": 0,
                    "status": "updated",
                    "reason": "ok"
                }
            mock_req.side_effect = sequenced

            test_argv = [
                'main.py',
                '--domains', domains_str,
                '--certbot-email', 'user@example.com',
                '--chunk-size', '100'
            ]
            with patch('sys.argv', test_argv):
                with self.assertRaises(SystemExit) as cm:
                    cb.main()
        self.assertEqual(mock_req.call_count, 4)
        suffixes = [str(i).zfill(5) for i in range(1, 5)]
        expected_names = [f"certbundle-{expected_hash}-{s}" for s in suffixes]
        called_names = [call.kwargs['cert_name'] for call in mock_req.call_args_list]
        self.assertListEqual(called_names, expected_names)
        self.assertEqual(cm.exception.code, 0)  # all succeeded


class TestMainIterationAndExitCodes(unittest.TestCase):
    @patch('main.subprocess.run')
    def test_mixed_results_continue_and_exit_code(self, mock_run):
        # Prepare 3 chunks via chunk-size=2 and 5 domains
        # We will return:
        #  - updated (returncode=0)
        #  - already-issued (returncode=1 with specific stderr)
        #  - failed other error (returncode=1 generic)
        side_effects = [
            MagicMock(returncode=0, stdout="OK", stderr=""),  # updated
            MagicMock(returncode=1, stdout="", stderr="already issued for this exact set of identifiers"),  # skipped
            MagicMock(returncode=1, stdout="", stderr="random failure")  # failed
        ]
        mock_run.side_effect = side_effects

        domains = [f"d{i}.example.com" for i in range(5)]
        domains_str = ",".join(domains)

        test_argv = [
            'main.py',
            '--domains', domains_str,
            '--certbot-email', 'user@example.com',
            '--chunk-size', '2'
        ]
        with patch('sys.argv', test_argv):
            with self.assertRaises(SystemExit) as cm:
                cb.main()

        # Expect 3 certbot invocations (3 chunks)
        self.assertEqual(mock_run.call_count, 3)
        # Exit code should be 1 due to at least one failed chunk
        self.assertEqual(cm.exception.code, 1)
