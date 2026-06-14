import axios from 'axios';
import * as crypto from 'crypto';
import { IncomingMessage, ServerResponse } from 'http';

const TUYA_ACCESS_ID = process.env.TUYA_ACCESS_ID || '';
const TUYA_ACCESS_SECRET = process.env.TUYA_ACCESS_SECRET || '';
const TUYA_DEVICE_ID = process.env.TUYA_DEVICE_ID || ''; // Alarme

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

async function tuyaRequest(method: string, path: string, body: any = {}): Promise<any> {
    const token = path.includes('/v1.0/token') ? '' : await getAccessToken();
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(8).toString('hex');
    const stringToSign = buildStringToSign(method, path, body);
    const signature = generateSignature(TUYA_ACCESS_ID, token, timestamp, nonce, stringToSign);

    const headers: Record<string, string> = {
        client_id: TUYA_ACCESS_ID,
        sign: signature,
        t: timestamp.toString(),
        sign_method: 'HMAC-SHA256',
        nonce: nonce,
        'Content-Type': 'application/json'
    };
    if (token) headers['access_token'] = token;

    const config: any = { method, url: `${TUYA_ENDPOINT}${path}`, headers };
    if (method.toUpperCase() === 'POST') config.data = body;

    const response = await axios(config);
    return response.data;
}

let cachedToken = '';
async function getAccessToken(): Promise<string> {
    if (cachedToken) return cachedToken;
    const data = await tuyaRequest('GET', '/v1.0/token?grant_type=1');
    if (data && data.success) {
        cachedToken = data.result.access_token;
        return cachedToken;
    }
    throw new Error(`Erro de autenticação Tuya: ${data.msg}`);
}

function getRequestBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
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
        return res.end(JSON.stringify({ success: false, message: 'Método não permitido.' }));
    }

    res.setHeader('Content-Type', 'application/json');

    try {
        const reqBody = await getRequestBody(req);
        const { target, action } = reqBody;

        if (target === 'alarme') {
            const path = `/v1.0/devices/${TUYA_DEVICE_ID}/commands`;
            const comandoAlarme = action === 'ligar' ? 'arm' : 'disarmed';
            const data = await tuyaRequest('POST', path, { commands: [{ code: 'master_mode', value: comandoAlarme }] });
            
            res.statusCode = data.success ? 200 : 500;
            return res.end(JSON.stringify({ success: data.success, message: data.msg }));
        } 
        
        if (target === 'portao') {
            // Nome da cena que criamos no app do celular
            const nomeCenaAlvo = `portao_${action}`;

            // 1. Descobre a lista de Cenas vinculadas à conta Tuya
            const listaCenas = await tuyaRequest('GET', '/v1.0/scenes');
            if (!listaCenas.success || !listaCenas.result) {
                res.statusCode = 500;
                return res.end(JSON.stringify({ success: false, message: `Falha ao listar cenas: ${listaCenas.msg}` }));
            }

            // 2. Procura a cena correspondente pelo nome correto
            const cenaEncontrada = listaCenas.result.find((s: any) => s.name === nomeCenaAlvo);
            if (!cenaEncontrada) {
                res.statusCode = 404;
                return res.end(JSON.stringify({ success: false, message: `Cena '${nomeCenaAlvo}' não encontrada no Smart Life.` }));
            }

            // 3. Executa o gatilho da cena na nuvem Tuya
            const disparo = await tuyaRequest('POST', `/v1.0/scenes/${cenaEncontrada.id}/trigger`);
            
            res.statusCode = disparo.success ? 200 : 500;
            return res.end(JSON.stringify({ success: disparo.success, message: disparo.msg }));
        }

        res.statusCode = 400;
        return res.end(JSON.stringify({ success: false, message: 'Alvo inválido.' }));

    } catch (error: any) {
        res.statusCode = 500;
        return res.end(JSON.stringify({ success: false, message: error.message }));
    }
}
