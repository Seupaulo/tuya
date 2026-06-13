import { VercelRequest, VercelResponse } from '@vercel/node';
import axios from 'axios';
import * as crypto from 'crypto';

const TUYA_ACCESS_ID = process.env.TUYA_ACCESS_ID || '';
const TUYA_ACCESS_SECRET = process.env.TUYA_ACCESS_SECRET || '';
const TUYA_DEVICE_ID = process.env.TUYA_DEVICE_ID || '';
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

    const { status } = req.body; // true para armar, false para desarmar
    if (typeof status !== 'boolean') return res.status(400).json({ success: false, message: 'Status inválido.' });

    try {
        const token = await getAccessToken();
        const path = `/v1.0/devices/${TUYA_DEVICE_ID}/commands`;
        const timestamp = Date.now();
        const nonce = crypto.randomBytes(8).toString('hex');

        // Configuração exata baseada nos parâmetros do seu alarme:
        // Se clicar em LIGAR (status true) -> envia 'arm'
        // Se clicar em DESLIGAR (status false) -> envia 'disarmed'
        const comandoAlarme = status ? 'arm' : 'disarmed';

        const body = {
            commands: [
                { 
                    code: 'master_mode', 
                    value: comandoAlarme 
                }
            ]
        };

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
            return res.status(500).json({ 
                success: false, 
                message: `Erro Tuya ${response.data.code}: ${response.data.msg}` 
            });
        }
    } catch (error: any) {
        return res.status(500).json({ success: false, message: error.message });
    }
}
