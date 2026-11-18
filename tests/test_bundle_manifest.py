"""Bundle-manifest type refusals preserve case state and clean CLI errors."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bec.cli import main
from bec.collection import Collection
from bec.storage import CaseError, create


NON_OBJECTS = (
    ('array', []), ('null', None), ('string', 'ordinary scalar'),
    ('number', 7), ('boolean', True),
)
ERROR = 'Bundle manifest must be a JSON object.'


class BundleManifestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.store = self.root / 'cases'
        self.case = create(self.store, 'TEST', 'analyst@example.com',
            '2026-01-01T00:00:00Z', '2026-01-02T00:00:00Z',
            dict(tenant='TEST', options=dict(defender=False)))
        for target in ('bec.graph.Graph.__init__', 'bec.graph.Graph.request',
                       'bec.workspace.Workspace.__init__', 'bec.workspace.Workspace.request',
                       'socket.create_connection', 'socket.getaddrinfo',
                       'socket.socket.connect', 'socket.socket.connect_ex'):
            self.enterContext(patch(target, side_effect=AssertionError('Offline manifest test: provider/network forbidden')))

    def write(self, name, value):
        path = self.root / (name + '.json')
        path.write_text(json.dumps(value) + '\n', encoding='utf-8')
        return path

    def tree(self):
        result = {}
        for path in [self.case.path, *sorted(self.case.path.rglob('*'))]:
            result[str(path.relative_to(self.case.path))] = (
                path.read_bytes() if path.is_file() else None, path.stat().st_mtime_ns)
        return result

    def test_non_object_manifests_fail_before_case_or_collection_mutation(self):
        collection = Collection(self.case)
        original_state = deepcopy(collection.state)
        original_remaining = collection.remaining
        original_case = self.tree()
        for label, value in NON_OBJECTS:
            with self.subTest(json_type=label):
                path = self.write(label, value)
                source = (path.read_bytes(), path.stat().st_mtime_ns)
                with self.assertRaises(CaseError) as caught:
                    collection.import_bundle(path)
                self.assertEqual(str(caught.exception), ERROR)
                self.assertEqual(collection.state, original_state)
                self.assertEqual(collection.remaining, original_remaining)
                self.assertEqual(collection.attempted, set())
                self.assertEqual(self.tree(), original_case)
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), source)

    def test_cli_translates_non_object_manifests_to_bounded_exit_one(self):
        # Normal case commands retain a lock file; create it before measuring refusal writes.
        with self.case.lock():
            pass
        original_case = self.tree()
        for label, value in NON_OBJECTS:
            with self.subTest(json_type=label):
                path = self.write(label, value)
                source = (path.read_bytes(), path.stat().st_mtime_ns)
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    code = main(['--root', str(self.store), 'collect', self.case.id, '--bundle', str(path)])
                self.assertEqual(code, 1)
                self.assertEqual(out.getvalue(), '')
                self.assertEqual(err.getvalue(), 'BEC: ' + ERROR + '\n')
                self.assertNotIn('Traceback', err.getvalue())
                self.assertEqual(self.tree(), original_case)
                self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), source)

    def test_mapping_manifest_accepts_a_harmless_empty_export(self):
        payload = self.write('empty-signins', [])
        bundle = self.write('bundle', dict(tenant='TEST', files=[
            dict(dataset='interactive', path=payload.name)]))
        inputs = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in (payload, bundle)}
        collection = Collection(self.case)
        collection.import_bundle(bundle)
        artifact, = self.case.manifest()['artifacts']
        self.assertEqual(artifact['dataset'], 'interactive')
        self.assertEqual(artifact['records'], 0)
        self.assertEqual(self.case.raw_path(artifact).read_bytes(), inputs[payload][0])
        self.assertEqual(collection.state['mode'], 'export')
        query = collection.state['queries']['file:interactive:' + payload.name]
        self.assertEqual((query['status'], query['records']), ('collected', 0))
        self.assertEqual(self.case.verify(), 1)
        for path, expected in inputs.items():
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), expected)


if __name__ == '__main__':
    unittest.main()
