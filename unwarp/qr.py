"""Optional, local QR export of the exact portable profile bytes."""

import io
import logging
import stat
import sys
from pathlib import Path

from .backends._files import Artifact, existing_file, publish


def export_qr(content: bytes, config: Path, mode: str, overwrite: bool) -> None:
    try:
        import segno
    except ImportError:
        raise ValueError(f'{config} is available. Install Segno for this interpreter, or run '
                         'python -m pip install ".[qr]" from the unwarp checkout') from None
    try:
        code = segno.make_qr(content, mode='byte', error='L')
    except segno.DataOverflowError:
        image_path = config.with_suffix('.conf.png')
        if overwrite and existing_file(image_path):
            publish(config.parent, {image_path: None})
        print(f'Profile is too large for one QR code ({len(content)} bytes). '
              f'Import {config} in the WireGuard app.', file=sys.stderr)
        return
    if mode == 'terminal':
        code.terminal(out=sys.stdout, compact=True)
        return
    image = io.BytesIO()
    code.save(image, kind='png', scale=6)
    path = config.with_suffix('.conf.png')
    data = image.getvalue()
    if existing_file(path) and not overwrite:
        if path.read_bytes() != data:
            raise ValueError(f'{path} already exists; use --overwrite to replace it')
        if stat.S_IMODE(path.lstat().st_mode) == 0o600:
            return
    publish(path.parent, {path: Artifact(data)})
    logging.getLogger(__name__).info('saved QR image %s', path)
