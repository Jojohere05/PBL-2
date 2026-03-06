/**
 * WebSocket Client for Real-time Scan Updates
 */

const WS_BASE_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/api/ws';

let socket = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 2000;

/**
 * Connect to WebSocket for scan updates
 */
export function connectWebSocket(scanId, callbacks = {}) {
  const { onProgress, onFinding, onComplete, onError, onConnect, onDisconnect } = callbacks;
  
  // Close existing connection
  if (socket) {
    socket.close();
  }
  
  const url = `${WS_BASE_URL}/scan/${scanId}`;
  
  try {
    socket = new WebSocket(url);
    
    socket.onopen = () => {
      console.log('WebSocket connected');
      reconnectAttempts = 0;
      if (onConnect) onConnect();
      
      // Start heartbeat
      startHeartbeat();
    };
    
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        switch (data.type) {
          case 'progress':
            if (onProgress) onProgress(data);
            break;
          case 'finding':
            if (onFinding) onFinding(data);
            break;
          case 'complete':
            if (onComplete) onComplete(data);
            break;
          case 'error':
            if (onError) onError(data);
            break;
          case 'pong':
            // Heartbeat response
            break;
          default:
            console.log('Unknown message type:', data.type);
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err);
      }
    };
    
    socket.onclose = (event) => {
      console.log('WebSocket closed:', event.code, event.reason);
      stopHeartbeat();
      if (onDisconnect) onDisconnect();
      
      // Attempt reconnection if not a clean close
      if (event.code !== 1000 && reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
        reconnectAttempts++;
        console.log(`Reconnecting... attempt ${reconnectAttempts}`);
        setTimeout(() => connectWebSocket(scanId, callbacks), RECONNECT_DELAY);
      }
    };
    
    socket.onerror = (error) => {
      console.error('WebSocket error:', error);
      if (onError) onError({ message: 'WebSocket connection error' });
    };
    
  } catch (err) {
    console.error('Failed to create WebSocket:', err);
    if (onError) onError({ message: 'Failed to connect to server' });
  }
  
  return socket;
}

/**
 * Disconnect WebSocket
 */
export function disconnectWebSocket() {
  stopHeartbeat();
  if (socket) {
    socket.close(1000, 'Client disconnect');
    socket = null;
  }
}

/**
 * Send message through WebSocket
 */
export function sendMessage(data) {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(data));
    return true;
  }
  return false;
}

/**
 * Check if WebSocket is connected
 */
export function isConnected() {
  return socket && socket.readyState === WebSocket.OPEN;
}

// Heartbeat mechanism
let heartbeatInterval = null;

function startHeartbeat() {
  stopHeartbeat();
  heartbeatInterval = setInterval(() => {
    sendMessage({ type: 'ping' });
  }, 30000); // Ping every 30 seconds
}

function stopHeartbeat() {
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
  }
}

export default {
  connectWebSocket,
  disconnectWebSocket,
  sendMessage,
  isConnected
};
