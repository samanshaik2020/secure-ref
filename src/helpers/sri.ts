import { createHash } from 'node:crypto';
import type { SriResult } from '../types';

export function sri(
    content: Buffer,
    algorithm: 'sha256' | 'sha384' | 'sha512' = 'sha384',
    url = ''
): SriResult {
    const hash = createHash(algorithm).update(content).digest('base64');
    const integrityAttribute = `${algorithm}-${hash}`;
    const htmlTag = url
        ? `<script src="${url}" integrity="${integrityAttribute}" crossorigin="anonymous"></script>`
        : `integrity="${integrityAttribute}" crossorigin="anonymous"`;
    return { url, hash, algorithm, integrityAttribute, htmlTag };
}
