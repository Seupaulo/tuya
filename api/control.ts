import axios from 'axios';
import * as crypto from 'crypto';
import { IncomingMessage, ServerResponse } from 'http';

const TUYA_ACCESS_ID = process.env.TUYA_ACCESS_ID || '';
const TUYA_ACCESS_SECRET = process.env.TUYA_ACCESS_SECRET || '';
const TUYA_DEVICE_ID = process.env.TUYA_DEVICE_ID || ''; // Alarme

// ID DO SEU INTERRUPTOR VIRTUAL CONFIGURADO
const TUYA_SWITCH_VIRTUAL_ID = "vdevo178140062586406";

// Mapeia cada ação do site para o código do canal correspondente na Tuya
const ACTION_MAP: Record<string, string> = {
    abrir: "switch_1",
    fechar: "switch_2",
    parar: "switch_3",
    travar: "switch_4"
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

function getRequestBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try { resolve(body ? JSON.parse(body) : {}); } catch (e) { resolve({}); }
        });
    });
}

export default async function handler(req: IncomingMessage, res: ServerResponse) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') { res.statusCode = 200; return res.end(); }
    if (req.method !== 'POST') {
        res.statusCode = 405;
        res.setHeader('Content-Type', 'application/json');
        return res.end(JSON.stringify({ success: false, message: 'Método não permitido.' }));
    }

    res.setHeader('Content-Type', 'application/json');

    try {
        const reqBody = await getRequestBody(req);
        const { target, action } = reqBody;
        const token = await getAccessToken();
        let path = '';
        let body = {};

        if (target === 'alarme') {
            path = `/v1.0/devices/${TUYA_DEVICE_ID}/commands`;
            const comandoAlarme = action === 'ligar' ? 'arm' : 'disarmed';
            body = { commands: [{ code: 'master_mode', value: comandoAlarme }] };
        } 
        else if (target === 'portao') {
            path = `/v1.0/devices/${TUYA_SWITCH_VIRTUAL_ID}/commands`;
            
            const codigoBotao = ACTION_MAP[action];
            if (!codigoBotao) {
                res.statusCode = 400;
                return res.end(JSON.stringify({ success: false, message: 'Ação do portão inválida.' }));
            }

            // Envia true para ligar o canal correspondente
            body = {
                commands: [{ 
                    code: codigoBotao, 
                    value: true 
                }]
            };
        } else {
            res.statusCode = 400;
            return res.end(JSON.stringify({ success: false, message: 'Alvo inválido.' }));
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

        res.statusCode = 200;
        if (response.data && response.data.success) {
            return res.end(JSON.stringify({ success: true }));
        } else {
            return res.end(JSON.stringify({ success: false, message: `Erro Tuya: ${response.data.msg}` }));
        }

    } catch (error: any) {
        res.statusCode = 500;
        return res.end(JSON.stringify({ success: false, message: error.message }));
    }
}
