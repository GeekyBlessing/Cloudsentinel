import axios from 'axios';

const BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({ baseURL: BASE, timeout: 30000 });

export const getPosture    = () => api.get('/api/v1/posture');
export const getFindings   = (params = {}) => api.get('/api/v1/findings', { params });
export const getFinding    = (id) => api.get(`/api/v1/findings/${id}`);
export const getAttackPath = () => api.get('/api/v1/attack-path');
export const getCompliance = () => api.get('/api/v1/compliance');
export const updateStatus  = (id, status, reason) =>
  api.patch(`/api/v1/findings/${id}/status`, { status, reason });
export const triggerScan   = (account_id) =>
  api.post('/api/v1/scans', { account_id });
