import { Injectable, signal } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface InterceptItem {
  id: string;
  timestamp: number;
  protocol: 'http' | 'https';
  method: string;
  host: string;
  port: number;
  path: string;
  url: string;
  headers: Record<string, string>;
  body: string;
}

export interface HistoryItem {
  id: string;
  timestamp: number;
  protocol: 'http' | 'https';
  method: string;
  host: string;
  port: number;
  path: string;
  url: string;
  requestHeaders: Record<string, string>;
  requestBody: string;
  responseStatus: number;
  responseStatusText: string;
  responseHeaders: Record<string, string>;
  responseBody: string;
  isResponseBase64: boolean;
  contentType: string;
  durationMs: number;
  size: number;
}

export interface ScannerIssue {
  id: string;
  ruleId: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'certain' | 'firm' | 'tentative';
  host: string;
  path: string;
  url: string;
  method: string;
  description: string;
  remediation: string;
  evidence: string;
  matchedItemId?: string;
  timestamp: number;
}

export interface IntruderResult {
  id: number;
  payload: string;
  status: number;
  statusText: string;
  length: number;
  durationMs: number;
  isAnomaly: boolean;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  responseHeaders: Record<string, string>;
  responseBody: string;
}

@Injectable({
  providedIn: 'root'
})
export class ProxyService {
  private ws: WebSocket | null = null;
  private wsUrl: string = '';
  private apiUrl: string = '';

  // Reactive State Signals
  public readonly connectionStatus = signal<'connected' | 'disconnected' | 'connecting'>('disconnected');
  public readonly interceptEnabled = signal<boolean>(false);
  public readonly pendingRequests = signal<InterceptItem[]>([]);
  public readonly history = signal<HistoryItem[]>([]);
  public readonly selectedItem = signal<HistoryItem | null>(null);

  // Passive Scanner Issues
  public readonly issues = signal<ScannerIssue[]>([]);
  public readonly selectedIssue = signal<ScannerIssue | null>(null);

  // Intruder Fuzzing State
  public readonly intruderResults = signal<IntruderResult[]>([]);
  public readonly selectedIntruderResult = signal<IntruderResult | null>(null);
  public readonly intruderRunning = signal<boolean>(false);
  public readonly intruderProgress = signal<{ current: number; total: number }>({ current: 0, total: 0 });

  constructor(private http: HttpClient) {
    const isDev = window.location.port === '4200';
    const host = isDev ? '127.0.0.1:8081' : window.location.host;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const httpProto = window.location.protocol === 'https:' ? 'https:' : 'http:';

    this.wsUrl = `${protocol}//${host}/ws`;
    this.apiUrl = `${httpProto}//${host}`;

    this.connectWebSocket();
    this.loadInitialStatus();
  }

  private connectWebSocket() {
    this.connectionStatus.set('connecting');
    try {
      this.ws = new WebSocket(this.wsUrl);

      this.ws.onopen = () => {
        this.connectionStatus.set('connected');
      };

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          this.handleWsMessage(msg);
        } catch (e) {
          console.error('[WS Parse Error]', e);
        }
      };

      this.ws.onclose = () => {
        this.connectionStatus.set('disconnected');
        setTimeout(() => this.connectWebSocket(), 3000);
      };

      this.ws.onerror = () => {
        this.connectionStatus.set('disconnected');
      };
    } catch {
      this.connectionStatus.set('disconnected');
      setTimeout(() => this.connectWebSocket(), 3000);
    }
  }

  private handleWsMessage(msg: any) {
    if (msg.type === 'init') {
      this.interceptEnabled.set(!!msg.data.interceptEnabled);
      if (Array.isArray(msg.data.history)) {
        this.history.set(msg.data.history);
      }
      if (Array.isArray(msg.data.pending)) {
        this.pendingRequests.set(msg.data.pending);
      }
      if (Array.isArray(msg.data.issues)) {
        this.issues.set(msg.data.issues);
      }
    } else if (msg.type === 'intercept_state') {
      this.interceptEnabled.set(!!msg.enabled);
    } else if (msg.type === 'intercept_request') {
      const current = this.pendingRequests();
      this.pendingRequests.set([msg.data, ...current]);
    } else if (msg.type === 'intercept_resolved') {
      const current = this.pendingRequests();
      this.pendingRequests.set(current.filter((item) => item.id !== msg.id));
    } else if (msg.type === 'history_item') {
      const current = this.history();
      this.history.set([msg.data, ...current.slice(0, 999)]);
    } else if (msg.type === 'history_cleared') {
      this.history.set([]);
      this.selectedItem.set(null);
    } else if (msg.type === 'scanner_issue') {
      const current = this.issues();
      this.issues.set([msg.data, ...current]);
    } else if (msg.type === 'issues_cleared') {
      this.issues.set([]);
      this.selectedIssue.set(null);
    } else if (msg.type === 'intruder_result') {
      const current = this.intruderResults();
      this.intruderResults.set([msg.data, ...current]);
      const prog = this.intruderProgress();
      this.intruderProgress.set({ current: prog.current + 1, total: prog.total });
    } else if (msg.type === 'intruder_complete') {
      this.intruderRunning.set(false);
    } else if (msg.type === 'intruder_stopped') {
      this.intruderRunning.set(false);
    }
  }

  private loadInitialStatus() {
    this.http.get<any>(`${this.apiUrl}/api/status`).subscribe({
      next: (res) => {
        this.interceptEnabled.set(res.interceptEnabled);
      },
      error: () => {}
    });

    this.http.get<HistoryItem[]>(`${this.apiUrl}/api/history`).subscribe({
      next: (list) => {
        if (Array.isArray(list)) {
          this.history.set(list);
        }
      },
      error: () => {}
    });

    this.http.get<ScannerIssue[]>(`${this.apiUrl}/api/issues`).subscribe({
      next: (list) => {
        if (Array.isArray(list)) {
          this.issues.set(list);
        }
      },
      error: () => {}
    });
  }

  public toggleIntercept(enabled?: boolean) {
    const newVal = enabled !== undefined ? enabled : !this.interceptEnabled();
    this.http.post<any>(`${this.apiUrl}/api/intercept/toggle`, { enabled: newVal }).subscribe({
      next: (res) => {
        this.interceptEnabled.set(res.interceptEnabled);
      }
    });
  }

  public forwardPending(id: string, headers: Record<string, string>, body: string) {
    this.http.post<any>(`${this.apiUrl}/api/intercept/action`, {
      id,
      action: 'forward',
      headers,
      body
    }).subscribe({
      next: () => {
        const current = this.pendingRequests();
        this.pendingRequests.set(current.filter(item => item.id !== id));
      }
    });
  }

  public dropPending(id: string) {
    this.http.post<any>(`${this.apiUrl}/api/intercept/action`, {
      id,
      action: 'drop'
    }).subscribe({
      next: () => {
        const current = this.pendingRequests();
        this.pendingRequests.set(current.filter(item => item.id !== id));
      }
    });
  }

  public clearHistory() {
    this.http.delete<any>(`${this.apiUrl}/api/history`).subscribe({
      next: () => {
        this.history.set([]);
        this.selectedItem.set(null);
      }
    });
  }

  public clearIssues() {
    this.http.delete<any>(`${this.apiUrl}/api/issues`).subscribe({
      next: () => {
        this.issues.set([]);
        this.selectedIssue.set(null);
      }
    });
  }

  public getIntruderPresets(): Observable<Record<string, string[]>> {
    return this.http.get<Record<string, string[]>>(`${this.apiUrl}/api/intruder/presets`);
  }

  public startIntruder(config: {
    templateUrl: string;
    method: string;
    headers: Record<string, string>;
    bodyTemplate: string;
    payloads: string[];
    concurrency?: number;
  }): Observable<any> {
    this.intruderResults.set([]);
    this.selectedIntruderResult.set(null);
    this.intruderRunning.set(true);
    this.intruderProgress.set({ current: 0, total: config.payloads.length });
    return this.http.post<any>(`${this.apiUrl}/api/intruder/start`, config);
  }

  public stopIntruder() {
    this.http.post<any>(`${this.apiUrl}/api/intruder/stop`, {}).subscribe({
      next: () => {
        this.intruderRunning.set(false);
      }
    });
  }

  public sendRepeaterRequest(reqData: { method: string; url: string; headers: Record<string, string>; body: string }): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/api/repeater/send`, reqData);
  }

  public getRootCaDownloadUrl(): string {
    return `${this.apiUrl}/cert`;
  }
}
