"""Offline regression for one-time leaf reuse across stale handles/processes."""
import multiprocessing
import tempfile
import unittest
from pathlib import Path
from entrovouch.signer import MerkleSigner, IndexReuse, verify_signature


def sign_worker(path, ready, start, result):
    try:
        signer = MerkleSigner.load(Path(path))
        ready.put(True)
        if not start.wait(15):
            raise RuntimeError('worker barrier timed out')
        result.put(('ok', signer.sign(b'concurrent')))
    except Exception as exc:
        result.put(('error', repr(exc)))


class StateConcurrency(unittest.TestCase):
    def test_stale_handles_do_not_reuse_leaf(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test-key.json'
            first = MerkleSigner.create(path, height=2)
            second = MerkleSigner.load(path)
            a, b = first.sign(b'a'), second.sign(b'b')
            self.assertEqual((a['leaf_index'], b['leaf_index']), (0, 1))
            self.assertTrue(verify_signature(b'a', a, expected_root=first.public_root))
            self.assertTrue(verify_signature(b'b', b, expected_root=first.public_root))
            with self.assertRaises(IndexReuse):
                first.sign(b'reuse', index=0)

    def test_concurrent_processes_reserve_distinct_leaves(self):
        ctx = multiprocessing.get_context('spawn')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test-key.json'
            signer = MerkleSigner.create(path, height=3)
            ready, result, start = ctx.Queue(), ctx.Queue(), ctx.Event()
            processes = [ctx.Process(target=sign_worker, args=(str(path), ready, start, result)) for _ in range(4)]
            try:
                for process in processes:
                    process.start()
                for _ in processes:
                    self.assertTrue(ready.get(timeout=15))
                start.set()
                signatures = []
                for _ in processes:
                    status, value = result.get(timeout=20)
                    self.assertEqual(status, 'ok', value)
                    signatures.append(value)
                self.assertEqual(sorted(s['leaf_index'] for s in signatures), [0, 1, 2, 3])
                for signature in signatures:
                    self.assertTrue(verify_signature(b'concurrent', signature, expected_root=signer.public_root))
                self.assertEqual(MerkleSigner.load(path).next_index, 4)
            finally:
                for process in processes:
                    process.join(timeout=5)
                    if process.is_alive():
                        process.terminate()
                        process.join()


if __name__ == '__main__':
    unittest.main()
