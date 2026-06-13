import { VercelRequest, VercelResponse } from '@vercel/node';
import axios from 'axios';
import * as crypto from 'crypto';

const TUYA_ACCESS_ID = process.env.TUYA_ACCESS_ID || '';
const TUYA_ACCESS_SECRET = process.env.TUYA_ACCESS_SECRET || '';
const TUYA_DEVICE_ID = process.env.TUYA_DEVICE_ID || ''; // Alarme
const TUYA_DEVICE_RF_ID = process.env.TUYA_DEVICE_RF_ID || ''; // Hub EKAZA Pai
const TUYA_SUB_PORTAO_ID = process.env.TUYA_SUB_PORTAO_ID || ''; // Controle Virtual Filho

const KEY_MAP: Record<string, string> = {
    abrir: process.env.KEY_PORTAO_ABRIR || '1',
    fechar: process.env.KEY_PORTAO_FECHAR || '2',
    parar: process.env.KEY_PORTAO_PARAR || '3',
    travar: process.env.KEY_PORTAO_TRAVAR || '4'
};

const TUYA_ENDPOINT = 'https://openapi.tuyaus.com';

function getContentHash(body: any): string {
    if (!body || Object.keys(body).length === 0) {
        return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    }
    return crypto.createHash('sha256').update(JSON.stringify(body), 'utf8').digest('hex');
}

function buildStringToSign(method: string, path: string, body: any = {}): string {
    const contentHash = getContentHash(body);
    return `${method.toUpperCase()}\n${contentHash}\n\n${path}`;
}

function generateSignature(clientId: string, token: string, timestamp: number, nonce: string, stringToSign: string): string {
    const message = clientId + token + timestamp + nonce + stringToSign;
    return crypto.createHmac('sha256', TUYA_ACCESS_SECRET).update(message, 'utf8').digest('hex').toUpperCase();
}

async function getAccessToken(): Promise<string> {
    const path = '/v1.0/token?grant_type=1';
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(8).toString('hex');
    const stringToSign = buildStringToSign('GET', path);
    const signature = generateSignature(TUYA_ACCESS_ID, '', timestamp, nonce, stringToSign);

    const response = await axios.get(`${TUYA_ENDPOINT}${path}`, {
        headers: {
            client_id: TUYA_ACCESS_ID,
            sign: signature,
            t: timestamp.toString(),
            sign_method: 'HMAC-SHA256',
            nonce: nonce
        }
    });

    if (response.data && response.data.success) {
        return response.data.result.access_token;
    }
    throw new Error(`Erro na Autenticação Tuya: ${response.data.msg}`);
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') return res.status(200).end();
    if (req.method !== 'POST') return res.status(405).json({ success: false, message: 'Método não permitido.' });

    const { target, action } = req.body; 

    try {
        const token = await getAccessToken();
        let path = '';
        let body = {};

        if (target === 'alarme') {
            path = `/v1.0/devices/${TUYA_DEVICE_ID}/commands`;
            const comandoAlarme = action === 'ligar' ? 'arm' : 'disarmed';
            body = {
                commands: [{ code: 'master_mode', value: comandoAlarme }]
            };
        } 
        else if (target === 'portao') {
            // O comando de RF deve ser enviado para o Hub Pai (EKAZA)
            path = `/v1.0/devices/${TUYA_DEVICE_RF_ID}/commands`;
            
            const keyId = KEY_MAP[action] || '1';
            
            // Monta a string de comando oficial de RF baseada no ID do sub-dispositivo
            const rfValueObj = {
                control: "rf_send",
                sub_id: TUYA_SUB_PORTAO_ID,
                key_id: keyId
            };

            body = {
                commands: [{ 
                    code: 'ir_send', 
                    value: JSON.stringify(rfValueObj) 
                }]
            };
        } else {
            return res.status(400).json({ success: false, message: 'Alvo inválido.' });
        }

        const timestamp = Date.now();
        const nonce = crypto.randomBytes(8).toString('hex');
        const stringToSign = buildStringToSign('POST', path, body);
        const signature = generateSignature(TUYA_ACCESS_ID, token, timestamp, nonce, stringToSign);

        const response = await axios.post(`${TUYA_ENDPOINT}${path}`, body, {
            headers: {
                client_id: TUYA_ACCESS_ID,
                access_token: token,
                sign: signature,
                t: timestamp.toString(),
                sign_method: 'HMAC-SHA256',
                nonce: nonce,
                'Content-Type': 'application/json'
            }
        });

        if (response.data && response.data.success) {
            return res.status(200).json({ success: true });
        } else {
            return res.status(500).json({ success: false, message: `Erro Tuya: ${response.data.msg} (Código: ${response.data.code})` });
        }
    } catch (error: any) {
        return res.status(500).json({ success: false, message: error.message });
    }
}
