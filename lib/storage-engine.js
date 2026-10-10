import fs from 'fs';
import path from 'path';
import os from 'os';

export class StorageEngine {
  constructor(options = {}) {
    this.spillThreshold = options.spillThreshold || 512 * 1024; // 512 KB
    this.maxMemoryPreview = options.maxMemoryPreview || 64 * 1024; // 64 KB preview
    this.blobDir = options.blobDir || path.join(os.tmpdir(), 'asta-sec-blobs');

    if (!fs.existsSync(this.blobDir)) {
      try {
        fs.mkdirSync(this.blobDir, { recursive: true });
      } catch {}
    }
  }

  isTextContent(contentType = '') {
    if (!contentType) return false;
    const ct = contentType.toLowerCase();
    return (
      ct.includes('text') ||
      ct.includes('json') ||
      ct.includes('xml') ||
      ct.includes('javascript') ||
      ct.includes('html') ||
      ct.includes('urlencoded')
    );
  }

  processBody(id, type, buffer, contentType = '') {
    const size = buffer.length;
    const isText = this.isTextContent(contentType);

    if (size > this.spillThreshold) {
      const filename = `blob_${id}_${type}_${Date.now()}.bin`;
      const filePath = path.join(this.blobDir, filename);

      try {
        fs.writeFileSync(filePath, buffer);
      } catch (err) {
        console.error('[StorageEngine] Failed to spill blob to disk:', err);
      }

      const previewBuf = buffer.subarray(0, this.maxMemoryPreview);
      const previewText = isText
        ? previewBuf.toString('utf8') + `\n\n[... Payload exceeds 512 KB: ${size} bytes spilled to ${filename} ...]`
        : previewBuf.toString('base64');

      return {
        size,
        isSpilled: true,
        spillPath: filePath,
        body: previewText,
        isBase64: !isText
      };
    }

    return {
      size,
      isSpilled: false,
      spillPath: null,
      body: isText ? buffer.toString('utf8') : buffer.toString('base64'),
      isBase64: !isText
    };
  }

  getFullBody(item) {
    if (item.isSpilled && item.spillPath && fs.existsSync(item.spillPath)) {
      try {
        const buf = fs.readFileSync(item.spillPath);
        return item.isResponseBase64 ? buf.toString('base64') : buf.toString('utf8');
      } catch {
        return item.responseBody;
      }
    }
    return item.responseBody;
  }

  cleanup(item) {
    if (item && item.spillPath && fs.existsSync(item.spillPath)) {
      try {
        fs.unlinkSync(item.spillPath);
      } catch {}
    }
  }

  cleanupAll() {
    if (fs.existsSync(this.blobDir)) {
      try {
        const files = fs.readdirSync(this.blobDir);
        for (const f of files) {
          try {
            fs.unlinkSync(path.join(this.blobDir, f));
          } catch {}
        }
      } catch {}
    }
  }
}
