import unittest
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
