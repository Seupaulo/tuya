import { VercelRequest, VercelResponse } from '@vercel/node';
import axios from 'axios';
import * as crypto from 'crypto';

const TUYA_ACCESS_ID = process.env.TUYA_ACCESS_ID || '';
const TUYA_ACCESS_SECRET = process.env.TUYA_ACCESS_SECRET || '';
const TUYA_DEVICE_ID = process.env.TUYA_DEVICE_ID || ''; // Alarme
const TUYA_DEVICE_RF_ID = process.env.TUYA_DEVICE_RF_ID || ''; // Hub EKAZA Pai

// DICIONÁRIO CONFIGURADO COMO STRINGS ESCAPADAS BRUTAS (EXATAMENTE COMO NO SEU LOG)
const RF_PAYLOADS: Record<string, string> = {
    abrir: '{"rf_type":"sub_2g","mode":0,"key1":{"times":6,"intervals":0,"delay":0,"code":"cyE3QVRrRE93SG5BamREUVVFNUE5WVFPd0U1QXprRERRRTdBVGtERFFFNUF6c0JPUU1OQVRrRE93SG5BanNCT1FNN0FlY0NPd0huQWpzQk9RTTVBdzBCT1FNTkFUa0REUkVOQVRrRE93RTVBdzBCT1FNTkFUa0RPd0U1QXcwQk9RTTdBUT09"},"feq":0,"rate":0,"control":"rfstudy_send","ver":"2"}',
    fechar: '{"rf_type":"sub_2g","mode":0,"key1":{"times":6,"intervals":0,"delay":0,"code":"UiBBTUFlTUNSZ0hqQWlvRDFRQXFBd3dCREFFcUF5b0REQUVNQWVNQ1JnSGpBZ3dCNHdKR0FlTUNSZ0hqQWd3QjR3SkdBZU1DREFIakFrWUI0d0lxQXd3QkRBSGpBZ3dCS2dOR0FlTUNEQUhqQWtZQjR3SkdBZU1DS2dNTUFzb0QxUUFNQVE9PQ=="},"feq":0,"rate":0,"control":"rfstudy_send","ver":"2"}',
    parar: '{"rf_type":"sub_2g","mode":0,"key1":{"times":6,"intervals":0,"delay":0,"code":"Y3lFN0FUa0RPd0huQWprRERRRTVBOVlBT3dFNUF6a0REUUU3QVRrRERRRTVBenNCT1FNTkFUa0RPd0huQWpzQk9RTTdBZWNDT3dIbkFqc0JPUU01QXcwQk9RTU5BVGtERFJFTkFUa0RPd0U1QXcwQk9RTU5BVGtET3dFNUF3MEJPUU03QVE9PQ=="},"feq":0,"rate":0,"control":"rfstudy_send","ver":"2"}',
    travar: '{"rf_type":"sub_2g","mode":0,"key1":{"times":6,"intervals":0,"delay":0,"code":"Q3lBTkFmOENRQUgvQXY4QzFBRC9BZzBCTFFIL0F2OENERUVORWY4Q1FBSC9BZzBCL3dKQUFmOENERFFIL0FrQUIvd0lOQWY4Q1FBSC9BZzBCL3dML0F0Z0FEUUgvQWtBQi93TC9BdGdBL3dJTkFRMEIvd0lOQWY4Q1FBSC9BZzBCL3dKQUFRPT0="},"feq":0,"rate":0,"control":"rfstudy_send","ver":"2"}'
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
            path = `/v1.0/devices/${TUYA_DEVICE_RF_ID}/commands`;
            
            const stringBrutaPayload = RF_PAYLOADS[action];
            if (!stringBrutaPayload) {
                return res.status(400).json({ success: false, message: 'Ação RF inválida.' });
            }

            // Injeta a string estática diretamente sem conversões extras do interpretador JSON
            body = {
                commands: [{ 
                    code: 'ir_send', 
                    value: stringBrutaPayload
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
            return res.status(500).json({ success: false, message: `Erro Tuya ${response.data.code}: ${response.data.msg}` });
        }
    } catch (error: any) {
        return res.status(500).json({ success: false, message: error.message });
    }
}
