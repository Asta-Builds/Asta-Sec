import { Component, inject, signal, computed, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ProxyService, HistoryItem, InterceptItem, ScannerIssue, IntruderResult } from './services/proxy.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App implements OnInit {
  public proxyService = inject(ProxyService);

  // Active navigation tab
  public activeTab = signal<'intercept' | 'history' | 'repeater' | 'intruder' | 'issues' | 'decoder' | 'setup'>('history');

  // History search and filtering
  public searchQuery = signal<string>('');
  public filterType = signal<'all' | 'http' | 'https' | 'errors'>('all');

  public filteredHistory = computed(() => {
    const list = this.proxyService.history();
    const q = this.searchQuery().toLowerCase().trim();
    const type = this.filterType();

    return list.filter(item => {
      // Type filter
      if (type === 'http' && item.protocol !== 'http') return false;
      if (type === 'https' && item.protocol !== 'https') return false;
      if (type === 'errors' && item.responseStatus < 400) return false;

      // Text search
      if (!q) return true;
      return (
        item.method.toLowerCase().includes(q) ||
        item.host.toLowerCase().includes(q) ||
        item.path.toLowerCase().includes(q) ||
        item.url.toLowerCase().includes(q) ||
        item.responseStatus.toString().includes(q) ||
        (item.contentType && item.contentType.toLowerCase().includes(q))
      );
    });
  });

  // Selected History Item Details View Tab ('headers' | 'raw' | 'body')
  public historyReqView = signal<'headers' | 'raw' | 'body'>('headers');
  public historyResView = signal<'headers' | 'raw' | 'body' | 'preview'>('headers');

  // Intercept View State
  public interceptActiveIndex = signal<number>(0);
  public interceptEditHeaders = signal<string>('');
  public interceptEditBody = signal<string>('');
  public interceptSubView = signal<'raw' | 'headers'>('raw');

  // Repeater State
  public repeaterMethod = signal<string>('GET');
  public repeaterUrl = signal<string>('https://httpbin.org/get');
  public repeaterHeaders = signal<string>('User-Agent: ASTA-SEC-Repeater/2.0\nAccept: application/json');
  public repeaterBody = signal<string>('');
  public repeaterLoading = signal<boolean>(false);
  public repeaterResponse = signal<any | null>(null);

  // Intruder (Fuzzing) State
  public intruderMethod = signal<string>('GET');
  public intruderUrl = signal<string>('https://httpbin.org/get?user=§FUZZ§');
  public intruderHeaders = signal<string>('User-Agent: ASTA-SEC-Intruder/2.0\nAccept: application/json');
  public intruderBody = signal<string>('');
  public intruderPayloadsText = signal<string>('admin\nlogin\ntest\ndev\nsecret');
  public intruderConcurrency = signal<number>(5);
  public intruderSelectedPreset = signal<string>('');
  public presetsList = signal<Record<string, string[]>>({});
  public intruderResultReqView = signal<'headers' | 'raw' | 'body'>('headers');
  public intruderResultResView = signal<'headers' | 'raw' | 'body'>('body');

  // Passive Scanner Issues State
  public severityFilter = signal<'all' | 'critical' | 'high' | 'medium' | 'low' | 'info'>('all');

  public filteredIssues = computed(() => {
    const list = this.proxyService.issues();
    const sev = this.severityFilter();
    if (sev === 'all') return list;
    return list.filter(i => i.severity === sev);
  });

  public issueStats = computed(() => {
    const list = this.proxyService.issues();
    return {
      critical: list.filter(i => i.severity === 'critical').length,
      high: list.filter(i => i.severity === 'high').length,
      medium: list.filter(i => i.severity === 'medium').length,
      low: list.filter(i => i.severity === 'low').length,
      info: list.filter(i => i.severity === 'info').length,
      total: list.length
    };
  });

  // Decoder State
  public decoderInput = signal<string>('');
  public decoderOutput = signal<string>('');
  public decoderActiveAction = signal<string>('');

  ngOnInit() {
    this.proxyService.getIntruderPresets().subscribe({
      next: (presets) => {
        if (presets) this.presetsList.set(presets);
      },
      error: () => {}
    });
  }

  // ----------------------------------------
  // Intercept Actions
  // ----------------------------------------
  public get currentInterceptItem(): InterceptItem | null {
    const pending = this.proxyService.pendingRequests();
    if (pending.length === 0) return null;
    const idx = Math.min(this.interceptActiveIndex(), pending.length - 1);
    const item = pending[idx] || null;
    if (item && !this.interceptEditHeaders()) {
      this.initInterceptEdit(item);
    }
    return item;
  }

  public initInterceptEdit(item: InterceptItem) {
    let hdrText = '';
    for (const [k, v] of Object.entries(item.headers)) {
      hdrText += `${k}: ${v}\n`;
    }
    this.interceptEditHeaders.set(hdrText.trim());
    this.interceptEditBody.set(item.body || '');
  }

  public forwardCurrentIntercept() {
    const item = this.currentInterceptItem;
    if (!item) return;

    const rawHdr = this.interceptEditHeaders();
    const parsedHeaders: Record<string, string> = {};
    const lines = rawHdr.split('\n');
    for (const line of lines) {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const k = line.substring(0, idx).trim().toLowerCase();
        const v = line.substring(idx + 1).trim();
        parsedHeaders[k] = v;
      }
    }

    this.proxyService.forwardPending(item.id, parsedHeaders, this.interceptEditBody());
    this.interceptEditHeaders.set('');
    this.interceptEditBody.set('');
  }

  public dropCurrentIntercept() {
    const item = this.currentInterceptItem;
    if (!item) return;
    this.proxyService.dropPending(item.id);
    this.interceptEditHeaders.set('');
    this.interceptEditBody.set('');
  }

  // ----------------------------------------
  // History Actions
  // ----------------------------------------
  public selectHistoryItem(item: HistoryItem) {
    this.proxyService.selectedItem.set(item);
  }

  public sendToRepeater(item: HistoryItem) {
    this.repeaterMethod.set(item.method);
    this.repeaterUrl.set(item.url);

    let hdrs = '';
    for (const [k, v] of Object.entries(item.requestHeaders)) {
      hdrs += `${k}: ${v}\n`;
    }
    this.repeaterHeaders.set(hdrs.trim());
    this.repeaterBody.set(item.requestBody || '');
    this.repeaterResponse.set(null);

    this.activeTab.set('repeater');
  }

  public sendToIntruder(item: HistoryItem) {
    this.intruderMethod.set(item.method);
    let markedUrl = item.url;
    if (markedUrl.includes('=')) {
      markedUrl = markedUrl.replace(/=([^&]+)/, '=§$1§');
    } else {
      markedUrl += markedUrl.includes('?') ? '&param=§FUZZ§' : '?param=§FUZZ§';
    }
    this.intruderUrl.set(markedUrl);

    let hdrs = '';
    for (const [k, v] of Object.entries(item.requestHeaders)) {
      hdrs += `${k}: ${v}\n`;
    }
    this.intruderHeaders.set(hdrs.trim());
    this.intruderBody.set(item.requestBody || '');

    this.activeTab.set('intruder');
  }

  public formatRawRequest(item: HistoryItem): string {
    let out = `${item.method} ${item.path} HTTP/1.1\nHost: ${item.host}\n`;
    for (const [k, v] of Object.entries(item.requestHeaders)) {
      if (k.toLowerCase() !== 'host') {
        out += `${k}: ${v}\n`;
      }
    }
    if (item.requestBody) {
      out += `\n${item.requestBody}`;
    }
    return out;
  }

  public formatRawResponse(item: HistoryItem): string {
    let out = `HTTP/1.1 ${item.responseStatus} ${item.responseStatusText}\n`;
    for (const [k, v] of Object.entries(item.responseHeaders)) {
      out += `${k}: ${v}\n`;
    }
    if (item.responseBody) {
      out += `\n${item.responseBody}`;
    }
    return out;
  }

  // ----------------------------------------
  // Repeater Actions
  // ----------------------------------------
  public sendRepeater() {
    this.repeaterLoading.set(true);
    this.repeaterResponse.set(null);

    const rawHdrs = this.repeaterHeaders();
    const headers: Record<string, string> = {};
    const lines = rawHdrs.split('\n');
    for (const l of lines) {
      const idx = l.indexOf(':');
      if (idx > 0) {
        const k = l.substring(0, idx).trim().toLowerCase();
        const v = l.substring(idx + 1).trim();
        headers[k] = v;
      }
    }

    this.proxyService.sendRepeaterRequest({
      method: this.repeaterMethod(),
      url: this.repeaterUrl(),
      headers,
      body: this.repeaterBody()
    }).subscribe({
      next: (res) => {
        this.repeaterLoading.set(false);
        this.repeaterResponse.set(res);
      },
      error: (err) => {
        this.repeaterLoading.set(false);
        this.repeaterResponse.set({
          status: 500,
          statusText: 'Internal Error',
          headers: {},
          body: err.message,
          durationMs: 0,
          size: 0
        });
      }
    });
  }

  // ----------------------------------------
  // Intruder Actions
  // ----------------------------------------
  public applyPreset(name: string) {
    const list = this.presetsList()[name];
    if (list && list.length > 0) {
      this.intruderPayloadsText.set(list.join('\n'));
      this.intruderSelectedPreset.set(name);
    }
  }

  public addMarkerToUrl() {
    const curr = this.intruderUrl();
    this.intruderUrl.set(curr + '§FUZZ§');
  }

  public startIntruder() {
    const rawHdrs = this.intruderHeaders();
    const headers: Record<string, string> = {};
    const lines = rawHdrs.split('\n');
    for (const l of lines) {
      const idx = l.indexOf(':');
      if (idx > 0) {
        const k = l.substring(0, idx).trim().toLowerCase();
        const v = l.substring(idx + 1).trim();
        headers[k] = v;
      }
    }

    const payloads = this.intruderPayloadsText()
      .split('\n')
      .map(p => p.trim())
      .filter(p => p.length > 0);

    if (payloads.length === 0) {
      alert('Please enter at least one payload to launch the Intruder attack.');
      return;
    }

    this.proxyService.startIntruder({
      templateUrl: this.intruderUrl(),
      method: this.intruderMethod(),
      headers,
      bodyTemplate: this.intruderBody(),
      payloads,
      concurrency: this.intruderConcurrency()
    }).subscribe({
      error: (err) => {
        console.error('Failed to start intruder', err);
      }
    });
  }

  public stopIntruder() {
    this.proxyService.stopIntruder();
  }

  public selectIntruderResult(item: IntruderResult) {
    this.proxyService.selectedIntruderResult.set(item);
  }

  // ----------------------------------------
  // Issues Actions
  // ----------------------------------------
  public selectIssue(issue: ScannerIssue) {
    this.proxyService.selectedIssue.set(issue);
  }

  // ----------------------------------------
  // Decoder Actions
  // ----------------------------------------
  public runDecoder(action: string) {
    this.decoderActiveAction.set(action);
    const input = this.decoderInput();

    try {
      switch (action) {
        case 'url_encode':
          this.decoderOutput.set(encodeURIComponent(input));
          break;
        case 'url_decode':
          this.decoderOutput.set(decodeURIComponent(input));
          break;
        case 'base64_encode':
          this.decoderOutput.set(btoa(input));
          break;
        case 'base64_decode':
          this.decoderOutput.set(atob(input));
          break;
        case 'hex_encode':
          let hex = '';
          for (let i = 0; i < input.length; i++) {
            hex += input.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
          }
          this.decoderOutput.set(hex.trim());
          break;
        case 'hex_decode':
          const cleanHex = input.replace(/\s+/g, '');
          let str = '';
          for (let i = 0; i < cleanHex.length; i += 2) {
            str += String.fromCharCode(parseInt(cleanHex.substr(i, 2), 16));
          }
          this.decoderOutput.set(str);
          break;
        default:
          this.decoderOutput.set(input);
      }
    } catch (e: any) {
      this.decoderOutput.set(`[Decoder Error]: ${e.message}`);
    }
  }

  public copyDecoderOutput() {
    navigator.clipboard.writeText(this.decoderOutput());
  }
}
