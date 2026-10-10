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

  public sendRepeaterRequest(reqData: { method: string; url: string; headers: Record<string, string>; body: string }): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/api/repeater/send`, reqData);
  }

  public getRootCaDownloadUrl(): string {
    return `${this.apiUrl}/cert`;
  }
}
