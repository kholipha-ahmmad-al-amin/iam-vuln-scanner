import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

export const submitScan = (payload) => api.post('/scans', payload)
export const listScans = (page = 1, pageSize = 10) =>
  api.get('/scans', { params: { page, page_size: pageSize } })
export const getScan = (scanId) => api.get(`/scans/${scanId}`)
export const getScanGraph = (scanId) => api.get(`/scans/${scanId}/graph`)
export const listRules = () => api.get('/rules')

export default api
