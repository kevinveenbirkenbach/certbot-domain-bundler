import unittest
from unittest.mock import patch, MagicMock, call
import main as cb


class TestClassifyCertbotResult(unittest.TestCase):
    def test_updated_ok(self):
        status, reason = cb.classify_certbot_result(0, "some success output", "")
        self.assertEqual(status, "updated")
        self.assertEqual(reason, "ok")

    def test_skipped_no_change(self):
        status, reason = cb.classify_certbot_result(0, "Certificate not yet due for renewal", "")
        self.assertEqual(status, "skipped")
        self.assertEqual(reason, "no-change")

    def test_skipped_already_issued(self):
        status, reason = cb.classify_certbot_result(1, "", "already issued for this exact set of identifiers")
        self.assertEqual(status, "skipped")
        self.assertEqual(reason, "already-issued")

    def test_skipped_rate_limit(self):
        status, reason = cb.classify_certbot_result(1, "", "too many certificates")
        self.assertEqual(status, "skipped")
        self.assertEqual(reason, "rate-limit")

    def test_skipped_service_down(self):
        status, reason = cb.classify_certbot_result(1, "", "the service is down for maintenance or had an internal error")
        self.assertEqual(status, "skipped")
        self.assertEqual(reason, "service-down")

    def test_failed_other_error(self):
        status, reason = cb.classify_certbot_result(1, "", "random failure")
        self.assertEqual(status, "failed")
        self.assertEqual(reason, "other-error")


class TestRequestCert(unittest.TestCase):
    @patch('main.subprocess.run')
    def test_request_cert_webroot_updated(self, mock_run):
        # simulate successful run (updated)
        mock_run.return_value = MagicMock(returncode=0, stdout="done", stderr="")
        res = cb.request_cert(
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
        self.assertIn('--cert-name', called)
        self.assertIn('testname', called)
        self.assertIn('--webroot', called)
        self.assertIn('-w', called)
        self.assertIn('/tmp', called)
        self.assertIn('--test-cert', called)
        self.assertIn('-d', called)
        self.assertIn('example.com', called)
        self.assertEqual(res["status"], "updated")
        self.assertEqual(res["reason"], "ok")

    @patch('main.subprocess.run')
    def test_request_cert_dns_already_issued(self, mock_run):
        # simulate already issued
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="An unexpected error occurred: already issued for this exact set of identifiers"
        )
        res = cb.request_cert(
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
        self.assertEqual(res["status"], "skipped")
        self.assertEqual(res["reason"], "already-issued")
