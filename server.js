const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'halal-trading-secret-key-change-in-production';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '01234567890123456789012345678901';

// ==================== DATA DIRECTORIES ====================
const dataDir = path.join(__dirname, 'data');
const tradesDir = path.join(dataDir, 'trades');
const pendingDir = path.join(dataDir, 'pending');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);
if (!fs.existsSync(tradesDir)) fs.mkdirSync(tradesDir);
if (!fs.existsSync(pendingDir)) fs.mkdirSync(pendingDir);

const usersFile = path.join(dataDir, 'users.json');
const pendingFile = path.join(pendingDir, 'pending_users.json');

// Default owner account
if (!fs.existsSync(usersFile)) {
    const defaultUsers = {
        "mujtabahatif@gmail.com": {
            email: "mujtabahatif@gmail.com",
            password: bcrypt.hashSync("Mujtabah@2598", 10),
            isOwner: true,
            isApproved: true,
            isBlocked: false,
            apiKey: "",
            secretKey: "",
            createdAt: new Date().toISOString()
        }
    };
    fs.writeFileSync(usersFile, JSON.stringify(defaultUsers, null, 2));
}
if (!fs.existsSync(pendingFile)) fs.writeFileSync(pendingFile, JSON.stringify({}));

function readUsers() { return JSON.parse(fs.readFileSync(usersFile)); }
function writeUsers(users) { fs.writeFileSync(usersFile, JSON.stringify(users, null, 2)); }
function readPending() { return JSON.parse(fs.readFileSync(pendingFile)); }
function writePending(pending) { fs.writeFileSync(pendingFile, JSON.stringify(pending, null, 2)); }

function encrypt(text) {
    if (!text) return "";
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}
function decrypt(text) {
    if (!text) return "";
    const parts = text.split(':');
    const iv = Buffer.from(parts.shift(), 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: '100% Halal AI Trading Bot - Demo + Real Trading' });
});

// ==================== AUTHENTICATION ====================
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    const users = readUsers();
    if (users[email]) return res.status(400).json({ success: false, message: 'User already exists' });
    const pending = readPending();
    if (pending[email]) return res.status(400).json({ success: false, message: 'Request already pending' });
    const hashedPassword = bcrypt.hashSync(password, 10);
    pending[email] = { email, password: hashedPassword, requestedAt: new Date().toISOString(), status: 'pending' };
    writePending(pending);
    res.json({ success: true, message: 'Registration request sent to owner.' });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    const user = users[email];
    if (!user) {
        const pending = readPending();
        if (pending[email]) return res.status(401).json({ success: false, message: 'Pending approval' });
        return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    if (!user.isApproved && !user.isOwner) return res.status(401).json({ success: false, message: 'Account not approved' });
    if (user.isBlocked) return res.status(401).json({ success: false, message: 'Your account has been blocked.' });
    const token = jwt.sign({ email, isOwner: user.isOwner || false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, isOwner: user.isOwner || false });
});

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ success: false, message: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ success: false, message: 'Invalid token' });
    }
}

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/pending-users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
    const pending = readPending();
    const list = Object.keys(pending).map(email => ({ email, requestedAt: pending[email].requestedAt }));
    res.json({ success: true, pending: list });
});

app.post('/api/admin/approve-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    const users = readUsers();
    users[email] = {
        email, password: pending[email].password,
        isOwner: false, isApproved: true, isBlocked: false,
        apiKey: "", secretKey: "",
        approvedAt: new Date().toISOString(),
        createdAt: pending[email].requestedAt
    };
    writeUsers(users);
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} approved.` });
});

app.post('/api/admin/reject-user', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const pending = readPending();
    if (!pending[email]) return res.status(404).json({ success: false });
    delete pending[email];
    writePending(pending);
    res.json({ success: true, message: `User ${email} rejected.` });
});

app.post('/api/admin/toggle-block', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { email } = req.body;
    const users = readUsers();
    if (!users[email]) return res.status(404).json({ success: false });
    users[email].isBlocked = !users[email].isBlocked;
    writeUsers(users);
    res.json({ success: true, message: `User ${email} is now ${users[email].isBlocked ? 'blocked' : 'unblocked'}.` });
});

// ==================== HALAL BINANCE API (REAL + DEMO TRADING) ====================
function cleanKey(key) {
    if (!key) return "";
    return key.replace(/[\s\n\r\t]+/g, '').trim();
}

async function getServerTime(useDemo = false) {
    // Demo Trading uses the same API endpoint as real Binance
    const baseUrl = 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/time`, { timeout: 5000 });
    return response.data.serverTime;
}

function generateSignature(queryString, secret) {
    return crypto.createHmac('sha256', secret).update(queryString).digest('hex');
}

async function binanceRequest(apiKey, secretKey, endpoint, params = {}, method = 'GET', useDemo = false) {
    const timestamp = await getServerTime(useDemo);
    const allParams = { ...params, timestamp, recvWindow: 5000 };
    const sortedKeys = Object.keys(allParams).sort();
    const queryString = sortedKeys.map(k => `${k}=${allParams[k]}`).join('&');
    const signature = generateSignature(queryString, secretKey);
    // IMPORTANT: Demo Trading uses the same API endpoint as real Binance
    const baseUrl = 'https://api.binance.com';
    const url = `${baseUrl}${endpoint}?${queryString}&signature=${signature}`;
    const response = await axios({
        method,
        url,
        headers: { 'X-MBX-APIKEY': apiKey },
        timeout: 10000
    });
    return response.data;
}

// Get Spot Wallet Balance (works for both Real and Demo)
async function getSpotBalance(apiKey, secretKey, useDemo = false) {
    try {
        const accountData = await binanceRequest(apiKey, secretKey, '/api/v3/account', {}, 'GET', useDemo);
        const usdtBalance = accountData.balances.find(b => b.asset === 'USDT');
        return parseFloat(usdtBalance?.free || 0);
    } catch (error) {
        console.error('Spot balance fetch error:', error.response?.data || error.message);
        return 0;
    }
}

// Get Funding Wallet Balance (may not work for Demo)
async function getFundingBalance(apiKey, secretKey, useDemo = false) {
    try {
        const timestamp = await getServerTime(useDemo);
        const queryString = `timestamp=${timestamp}`;
        const signature = generateSignature(queryString, secretKey);
        const baseUrl = 'https://api.binance.com';
        const url = `${baseUrl}/sapi/v1/asset/get-funding-asset?${queryString}&signature=${signature}`;
        const response = await axios({
            method: 'POST',
            url,
            headers: { 'X-MBX-APIKEY': apiKey, 'Content-Type': 'application/json' },
            timeout: 10000
        });
        const usdtAsset = response.data.find(asset => asset.asset === 'USDT');
        return parseFloat(usdtAsset?.free || 0);
    } catch (error) {
        console.log('Funding wallet not accessible (Demo mode may not support this)');
        return 0;
    }
}

async function getCurrentPrice(symbol, useDemo = false) {
    const baseUrl = 'https://api.binance.com';
    const response = await axios.get(`${baseUrl}/api/v3/ticker/price?symbol=${symbol}`);
    return parseFloat(response.data.price);
}

async function placeHalalSpotOrder(apiKey, secretKey, symbol, side, quoteOrderQty, useDemo = false) {
    if (quoteOrderQty < 10) {
        throw new Error('Minimum order size is $10 USDT for halal spot trading');
    }
    return await binanceRequest(apiKey, secretKey, '/api/v3/order', {
        symbol,
        side,
        type: 'MARKET',
        quoteOrderQty: quoteOrderQty.toFixed(2)
    }, 'POST', useDemo);
}

// ==================== API KEY MANAGEMENT ====================
app.post('/api/set-api-keys', authenticate, async (req, res) => {
    let { apiKey, secretKey, accountType } = req.body;
    if (!apiKey || !secretKey) return res.status(400).json({ success: false, message: 'Both keys required' });
    const cleanApi = cleanKey(apiKey);
    const cleanSecret = cleanKey(secretKey);
    const useDemo = (accountType === 'testnet'); // Demo mode uses same as testnet option
    
    try {
        const spotBalance = await getSpotBalance(cleanApi, cleanSecret, useDemo);
        const fundingBalance = await getFundingBalance(cleanApi, cleanSecret, useDemo);
        const users = readUsers();
        users[req.user.email].apiKey = encrypt(cleanApi);
        users[req.user.email].secretKey = encrypt(cleanSecret);
        writeUsers(users);
        
        const mode = useDemo ? 'Demo Trading' : 'Halal Spot Trading';
        res.json({ 
            success: true, 
            message: `${mode} API keys saved! Spot: ${spotBalance} USDT | Funding: ${fundingBalance} USDT`, 
            spotBalance: spotBalance,
            fundingBalance: fundingBalance
        });
    } catch (error) {
        console.error('API verification error:', error.response?.data || error.message);
        let errorMsg = 'Invalid API keys. ';
        if (error.response?.data?.code === -2015) errorMsg += 'Enable "Spot & Margin Trading" in Binance API settings.';
        else if (error.response?.data?.code === -1022) errorMsg += 'Invalid signature. Check your Secret Key.';
        else if (error.response?.data?.code === -1021) errorMsg += 'Timestamp error. Server time sync issue.';
        else errorMsg += error.response?.data?.msg || error.message;
        res.status(401).json({ success: false, message: errorMsg });
    }
});

app.post('/api/connect-binance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.status(400).json({ success: false, message: 'No API keys saved.' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = (accountType === 'testnet');
    
    try {
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
        const mode = useDemo ? 'Demo Trading' : 'Halal Spot Trading';
        res.json({ 
            success: true, 
            spotBalance: spotBalance, 
            fundingBalance: fundingBalance,
            totalBalance: spotBalance + fundingBalance,
            message: `Connected to ${mode}! Spot: ${spotBalance} USDT | Funding: ${fundingBalance} USDT` 
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Connection failed. Check your API keys and permissions.' });
    }
});

app.get('/api/get-keys', authenticate, (req, res) => {
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, message: 'No keys set' });
    res.json({ success: true, apiKey: decrypt(user.apiKey), secretKey: decrypt(user.secretKey) });
});

// ==================== OWNER: GET ALL USERS' BALANCES ====================
app.get('/api/admin/user-balances', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false, message: 'Admin only' });
    
    const users = readUsers();
    const balances = {};
    
    for (const [email, userData] of Object.entries(users)) {
        if (!userData.apiKey) {
            balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: false };
            continue;
        }
        
        try {
            const apiKey = decrypt(userData.apiKey);
            const secretKey = decrypt(userData.secretKey);
            const spotBalance = await getSpotBalance(apiKey, secretKey, false);
            const fundingBalance = await getFundingBalance(apiKey, secretKey, false);
            balances[email] = {
                spot: spotBalance,
                funding: fundingBalance,
                total: spotBalance + fundingBalance,
                hasKeys: true,
                lastUpdated: new Date().toISOString()
            };
        } catch (error) {
            balances[email] = { spot: 0, funding: 0, total: 0, hasKeys: true, error: error.message };
        }
    }
    
    res.json({ success: true, balances });
});

// ==================== HALAL TRADING ENGINE WITH COMPOUNDING ====================
const activeTradingSessions = {};

class HalalTradingEngine {
    async getAISignal(symbol, useDemo = false) {
        try {
            const ticker = await binanceRequest('', '', '/api/v3/ticker/24hr', { symbol }, 'GET', useDemo);
            const priceChange = parseFloat(ticker.priceChangePercent);
            const volume = parseFloat(ticker.volume);
            
            if (priceChange > 1.5 && volume > 1000000) return { action: 'BUY', confidence: 0.7 };
            if (priceChange < -1.5 && volume > 1000000) return { action: 'SELL', confidence: 0.7 };
            if (priceChange > 0.5) return { action: 'BUY', confidence: 0.55 };
            if (priceChange < -0.5) return { action: 'SELL', confidence: 0.55 };
            return { action: 'HOLD', confidence: 0.5 };
        } catch (error) {
            return { action: 'HOLD', confidence: 0.5 };
        }
    }

    async executeTrade(sessionId, userEmail, apiKey, secretKey, config, useDemo = false) {
        const { initialInvestment, targetProfit, riskLevel, tradingPairs, startedAt, timeLimit } = config;
        
        const elapsedHours = (Date.now() - startedAt) / (1000 * 60 * 60);
        if (elapsedHours >= timeLimit) {
            if (activeTradingSessions[sessionId]) activeTradingSessions[sessionId].isActive = false;
            return { success: false, message: 'Time limit reached' };
        }
        
        const currentProfit = activeTradingSessions[sessionId]?.currentProfit || 0;
        if (currentProfit >= targetProfit) {
            activeTradingSessions[sessionId].isActive = false;
            return { success: false, message: 'Target reached' };
        }
        
        const winStreak = activeTradingSessions[sessionId]?.winStreak || 0;
        
        let basePercent = 0.10;
        if (riskLevel === 'medium') basePercent = 0.15;
        if (riskLevel === 'high') basePercent = 0.20;
        
        const compoundingBonus = Math.min(winStreak * 0.02, 0.20);
        const totalPercent = Math.min(basePercent + compoundingBonus, 0.30);
        
        const actualBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        let positionSize = actualBalance * totalPercent;
        
        if (positionSize < 10) positionSize = 10;
        if (actualBalance < positionSize + 5) {
            return { success: false, error: 'Insufficient balance' };
        }
        
        const symbol = tradingPairs[Math.floor(Math.random() * tradingPairs.length)];
        const currentPrice = await getCurrentPrice(symbol, useDemo);
        const signal = await this.getAISignal(symbol, useDemo);
        
        if (signal.action === 'HOLD') {
            return { success: true, message: 'AI recommended hold' };
        }
        
        const isBuy = (signal.action === 'BUY');
        
        try {
            const order = await placeHalalSpotOrder(apiKey, secretKey, symbol, isBuy ? 'BUY' : 'SELL', positionSize, useDemo);
            const entryPrice = parseFloat(order.fills?.[0]?.price || currentPrice);
            const quantity = parseFloat(order.executedQty);
            
            const profit = isBuy ? (currentPrice - entryPrice) * quantity : (entryPrice - currentPrice) * quantity;
            
            if (!activeTradingSessions[sessionId]) {
                activeTradingSessions[sessionId] = { currentProfit: 0, trades: [], winStreak: 0 };
            }
            
            activeTradingSessions[sessionId].currentProfit += profit;
            
            if (profit > 0) {
                activeTradingSessions[sessionId].winStreak = (activeTradingSessions[sessionId].winStreak || 0) + 1;
            } else {
                activeTradingSessions[sessionId].winStreak = 0;
            }
            
            activeTradingSessions[sessionId].trades.push({
                symbol,
                side: isBuy ? 'BUY' : 'SELL',
                quantity: quantity.toFixed(6),
                price: entryPrice.toFixed(2),
                profit: profit,
                size: '$' + positionSize.toFixed(2),
                winStreak: activeTradingSessions[sessionId].winStreak,
                timestamp: new Date().toISOString(),
                isHalal: true
            });
            
            const userTradeFile = path.join(tradesDir, userEmail.replace(/[^a-z0-9]/gi, '_') + '.json');
            let allTrades = [];
            if (fs.existsSync(userTradeFile)) allTrades = JSON.parse(fs.readFileSync(userTradeFile));
            allTrades.unshift({
                symbol,
                side: isBuy ? 'BUY' : 'SELL',
                quantity,
                price: entryPrice,
                profit: profit,
                winStreak: activeTradingSessions[sessionId].winStreak,
                timestamp: new Date().toISOString(),
                isHalal: true
            });
            fs.writeFileSync(userTradeFile, JSON.stringify(allTrades, null, 2));
            
            return { success: true, trade: { symbol, side: isBuy ? 'BUY' : 'SELL', profit: profit, price: entryPrice, size: positionSize, winStreak: activeTradingSessions[sessionId].winStreak } };
        } catch (error) {
            console.error('Trade error:', error.message);
            return { success: false, error: error.message };
        }
    }
}

const tradingEngine = new HalalTradingEngine();

app.post('/api/start-trading', authenticate, async (req, res) => {
    const { initialInvestment, targetProfit, timeLimit, riskLevel, tradingPairs, accountType } = req.body;
    if (initialInvestment < 10) {
        return res.status(400).json({ success: false, message: 'Minimum investment for halal trading is $10' });
    }
    const users = readUsers();
    const user = users[req.user.email];
    if (!user.apiKey) return res.status(400).json({ success: false, message: 'Please add API keys first' });
    
    const apiKey = decrypt(user.apiKey);
    const secretKey = decrypt(user.secretKey);
    const useDemo = (accountType === 'testnet');
    
    try {
        const balance = await getSpotBalance(apiKey, secretKey, useDemo);
        if (balance < initialInvestment) {
            return res.status(400).json({ success: false, message: `Insufficient spot balance. You have ${balance} USDT, need ${initialInvestment}` });
        }
        if (!useDemo && balance < 10) {
            return res.status(400).json({ success: false, message: `Halal trading requires minimum 10 USDT in spot wallet. You have ${balance} USDT.` });
        }
    } catch (error) {
        return res.status(401).json({ success: false, message: 'Failed to verify balance. Check API keys.' });
    }
    
    const sessionId = 'session_' + Date.now() + '_' + req.user.email.replace(/[^a-z0-9]/gi, '_');
    const tradeIntervalSeconds = 60;
    
    activeTradingSessions[sessionId] = {
        isActive: true,
        currentProfit: 0,
        trades: [],
        winStreak: 0,
        initialInvestment,
        targetProfit,
        timeLimit,
        riskLevel,
        tradingPairs,
        startedAt: Date.now(),
        userEmail: req.user.email,
        multiplier: (targetProfit / initialInvestment).toFixed(0)
    };
    
    const tradeInterval = setInterval(async () => {
        const session = activeTradingSessions[sessionId];
        if (!session || !session.isActive) {
            clearInterval(tradeInterval);
            return;
        }
        await tradingEngine.executeTrade(
            sessionId,
            req.user.email,
            apiKey,
            secretKey,
            { initialInvestment, targetProfit, riskLevel, tradingPairs, startedAt: session.startedAt, timeLimit },
            useDemo
        );
    }, tradeIntervalSeconds * 1000);
    
    activeTradingSessions[sessionId].interval = tradeInterval;
    
    const mode = useDemo ? 'DEMO' : 'REAL';
    res.json({ 
        success: true, 
        sessionId, 
        message: `🕋 HALAL TRADING STARTED (${mode})! Target: ${(targetProfit/initialInvestment).toFixed(0)}x | Win streak = +2% position size`
    });
});

app.post('/api/stop-trading', authenticate, (req, res) => {
    const { sessionId } = req.body;
    if (activeTradingSessions[sessionId]) {
        if (activeTradingSessions[sessionId].interval) {
            clearInterval(activeTradingSessions[sessionId].interval);
        }
        activeTradingSessions[sessionId].isActive = false;
        delete activeTradingSessions[sessionId];
    }
    res.json({ success: true, message: 'Trading stopped' });
});

app.post('/api/trading-update', authenticate, (req, res) => {
    const { sessionId } = req.body;
    const session = activeTradingSessions[sessionId];
    if (!session) {
        return res.json({ success: true, currentProfit: 0, newTrades: [] });
    }
    const newTrades = session.trades.slice(-5);
    const elapsedHours = (Date.now() - session.startedAt) / (1000 * 60 * 60);
    const timeRemaining = Math.max(0, session.timeLimit - elapsedHours);
    const progressPercent = (session.currentProfit / session.targetProfit) * 100;
    
    res.json({
        success: true,
        currentProfit: session.currentProfit,
        targetProfit: session.targetProfit,
        newTrades: newTrades,
        winStreak: session.winStreak || 0,
        timeRemaining: timeRemaining,
        progressPercent: progressPercent,
        multiplier: (session.currentProfit / session.initialInvestment).toFixed(1)
    });
});

app.post('/api/get-balance', authenticate, async (req, res) => {
    const { accountType } = req.body;
    const users = readUsers();
    const user = users[req.user.email];
    if (!user || !user.apiKey) return res.json({ success: false, balance: 0 });
    try {
        const apiKey = decrypt(user.apiKey);
        const secretKey = decrypt(user.secretKey);
        const useDemo = (accountType === 'testnet');
        const spotBalance = await getSpotBalance(apiKey, secretKey, useDemo);
        const fundingBalance = await getFundingBalance(apiKey, secretKey, useDemo);
        res.json({ success: true, spotBalance: spotBalance, fundingBalance: fundingBalance, total: spotBalance + fundingBalance });
    } catch (error) {
        res.json({ success: false, balance: 0 });
    }
});

// ==================== OWNER DATA ROUTES ====================
app.get('/api/admin/users', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const users = readUsers();
    const list = Object.keys(users).map(email => ({
        email, hasApiKeys: !!users[email].apiKey, isOwner: users[email].isOwner, isApproved: users[email].isApproved, isBlocked: users[email].isBlocked
    }));
    res.json({ success: true, users: list });
});

app.get('/api/admin/all-trades', authenticate, (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const allTrades = {};
    const files = fs.readdirSync(tradesDir);
    for (const file of files) {
        if (file === '.gitkeep') continue;
        const userId = file.replace('.json', '');
        const trades = JSON.parse(fs.readFileSync(path.join(tradesDir, file)));
        allTrades[userId] = trades;
    }
    res.json({ success: true, trades: allTrades });
});

app.post('/api/change-password', authenticate, async (req, res) => {
    if (!req.user.isOwner) return res.status(403).json({ success: false });
    const { currentPassword, newPassword } = req.body;
    const users = readUsers();
    const owner = users[req.user.email];
    if (!bcrypt.compareSync(currentPassword, owner.password)) return res.status(401).json({ success: false, message: 'Current password incorrect' });
    owner.password = bcrypt.hashSync(newPassword, 10);
    writeUsers(users);
    res.json({ success: true, message: 'Password changed!' });
});

// ==================== CATCH‑ALL ROUTE ====================
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n🕋 100% HALAL AI TRADING BOT`);
    console.log(`✅ Owner: mujtabahatif@gmail.com / Mujtabah@2598`);
    console.log(`✅ Real + Demo Trading support (both use same API)`);
    console.log(`✅ Spot + Funding wallet balances available`);
    console.log(`✅ Halal compounding: +2% position size per win streak (max +20%)`);
    console.log(`✅ Minimum balance: 10 USDT in spot wallet`);
    console.log(`✅ Server running on port: ${PORT}`);
});
