"""Stage mask3 plus reviewed lazy imports, excluding unrelated working changes."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import zipfile

CHANGES = (
    'nlp_engine/__init__.py',
    'nlp_engine/nlp_engine_provider.py',
    'nlp_engine/nlp_artifacts.py',
    'nlp_engine/no_op_nlp_engine.py',
    'nlp_engine/_spacy_types.py',
    'recognizer_registry/recognizer_registry.py',
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-wheel', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    args.output.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(args.baseline_wheel) as archive:
        metadata = archive.read('presidio_analyzer-2.2.366+ru.mask3.dist-info/METADATA').decode()
        assert '\nVersion: 2.2.366+ru.mask3\n' in metadata
        for name in archive.namelist():
            path = PurePosixPath(name)
            if path.parts[0] != 'presidio_analyzer' or name.endswith('/'):
                continue
            assert '..' not in path.parts and not path.is_absolute()
            destination = args.output / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(archive.read(name))
    for relative in CHANGES:
        shutil.copyfile(source / 'presidio_analyzer' / relative,
                        args.output / 'presidio_analyzer' / relative)
    project = (source / 'pyproject.toml').read_text()
    assert 'version = "2.2.366+ru.mask3"' in project
    (args.output / 'pyproject.toml').write_text(project.replace(
        'version = "2.2.366+ru.mask3"', 'version = "2.2.366+ru.mask4"', 1))
    shutil.copyfile(source / 'README.md', args.output / 'README.md')
    manifest = {'baseline_wheel_sha256': sha(args.baseline_wheel),
                'version': '2.2.366+ru.mask4', 'overlaid_files': list(CHANGES),
                'staging_script_sha256': sha(Path(__file__)),
                'files': {str(p.relative_to(args.output)): sha(p)
                          for p in sorted(args.output.rglob('*')) if p.is_file()}}
    (args.output / 'release-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'version': manifest['version'], 'files': len(manifest['files'])}))


if __name__ == '__main__':
    main()
