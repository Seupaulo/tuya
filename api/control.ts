import { VercelRequest, VercelResponse } from '@vercel/node';
import axios from 'axios';
import * as crypto from 'crypto';

// Configurações extraídas de forma segura das Variáveis de Ambiente da Vercel
const TUYA_ACCESS_ID = process.env.TUYA_ACCESS_ID || '';
const TUYA_ACCESS_SECRET = process.env.TUYA_ACCESS_SECRET || '';
const TUYA_DEVICE_ID = process.env.TUYA_DEVICE_ID || '';
const TUYA_ENDPOINT = 'https://openapi.tuyaus.com'; // Altere se o seu Data Center for EU ou CN

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
    throw new Error(`Erro de autenticação na Tuya: ${response.data.msg}`);
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
    // Configuração do CORS para permitir que o seu frontend acione a função
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, message: 'Método não permitido. Use POST.' });
    }

    const { status } = req.body;
    if (typeof status !== 'boolean') {
        return res.status(400).json({ success: false, message: 'O parâmetro "status" deve ser booleano.' });
    }

    try {
        const token = await getAccessToken();
        const path = `/v1.0/devices/${TUYA_DEVICE_ID}/commands`;
        const timestamp = Date.now();
        const nonce = crypto.randomBytes(8).toString('hex');

        const body = {
            commands: [
                {
                    code: 'switch_1', // Verifique no painel Tuya se o seu código é switch, switch_1 ou power
                    value: status
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
            return res.status(200).json({ success: true, result: response.data.result });
        } else {
            return res.status(500).json({ success: false, message: `Erro Tuya: ${response.data.msg}` });
        }

    } catch (error: any) {
        return res.status(500).json({ success: false, message: error.message });
    }
}