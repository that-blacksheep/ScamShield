import axios from 'axios'

const api = axios.create({ baseURL: 'http://127.0.0.1:8000' })

export const scanOffer  = (payload)              => api.post('/api/check', payload)
export const getStats   = ()                     => api.get('/api/stats')
export const getHistory = (limit = 20, offset = 0) => api.get('/api/history', { params: { limit, offset } })