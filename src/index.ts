// src/index.ts
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { expressjwt, Request as JWTRequest } from "express-jwt";
import jwt from "jsonwebtoken";
import { PublicKey } from '@solana/web3.js';
import nacl from 'tweetnacl';
dotenv.config();



const PORT = process.env.PORT || 3000;
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!!;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET!!;
const JWT_TOKEN_ALGO = "HS256";
const TOKEN_EXP = "5m"; // "10s" // - for demonstration purposes
const REFRESH_TOKEN_EXP =  "1h"; // "5m"; // - for demonstration purposes

const app = express();
const prisma = new PrismaClient();

// reference: https://github.com/wgzhaocv/auth/blob/315376ca41db8b18cb0fc852a8e732a03a2da8a0/src/jwt.ts#L41 

// TODO: add audience, claims, etc. for admin and all that stuff

// in prod this would be the address of the react front-end
app.use(cors({
    origin: ['http://localhost:3000', 'https://localhost:3001'],
    credentials: true,
}));

app.use(express.json());

// apply JWT token authentication to all methods except /login, /register, /token 
// /token has its own authentication for the refreshToken which is explicitly configured
/*app.use(expressjwt({
    secret: ACCESS_TOKEN_SECRET,
    algorithms: [JWT_TOKEN_ALGO]
}).unless({ path: ["/login", "/register", "/token"]}))
*/

app.post('/add', 
    expressjwt({ secret: ACCESS_TOKEN_SECRET, algorithms: [JWT_TOKEN_ALGO] }),
    async (req, res) => {
        console.log("/add called");
        const { x, y } = req.body;
        const result = x + y;
        res.json({ result });
    }
);


// /register and /login will be replaced with tiplink stuff - this is not permanent, just POC
/*app.post('/register', async (req, res) => {
    console.log("/register called");
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword
            }
        });
        res.status(201).json(user);
    } catch (error) {
        res.status(400).json({ error: 'User already exists' });
    }
}); */

// /register and /login will be replaced with tiplink stuff - this is not permanent, just POC
app.post('/login', async (req, res) => {
    console.log("/login called");
    
    const { message, signature, publicKey } = req.body;

    if (!message || !signature || !publicKey) {
        return res.status(400);
    }

    try {
        const sigIsValid = verifySignature(message, signature, publicKey);
        if (sigIsValid) {
            // TODO: create user on first login
            const token = jwt.sign({ publicKey }, ACCESS_TOKEN_SECRET, { expiresIn: TOKEN_EXP }); // "10m"
            const refreshToken = jwt.sign({ publicKey }, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXP }); // "1h"
            return res.json({ token, refreshToken });
        } else {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
    }
    catch(e) {
        return res.status(500);
    }
});



// refresh token endpoint
app.post('/token', 
    expressjwt({ secret: REFRESH_TOKEN_SECRET, algorithms: [JWT_TOKEN_ALGO] }),
    async (req, res) => { 
        console.log("/token called");
        const publicKey = (req as any)?.auth?.publicKey;
        if (publicKey == null) {
            return res.status(403);
        }
        const token = jwt.sign({ publicKey }, ACCESS_TOKEN_SECRET, { expiresIn: TOKEN_EXP }); // "10,"
        const refreshToken = jwt.sign({ publicKey }, REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXP }); // "1h"
        return res.json({ token, refreshToken });
    }
);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


function verifySignature(message: string, signature: string, publicKeyString: string): boolean {
    const publicKey = new PublicKey(publicKeyString).toBytes();
    const encoder = new TextEncoder();
    const encodedMessage = encoder.encode(message);
    const encodedSignature = encoder.encode(signature);
    return nacl.sign.detached.verify(encodedMessage, encodedSignature, publicKey);
};