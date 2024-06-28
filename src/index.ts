// src/index.ts
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import { expressjwt, Request as JWTRequest } from "express-jwt";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET!!;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET!!;
const JWT_TOKEN_ALGO = "HS256";

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
app.use(expressjwt({
    secret: ACCESS_TOKEN_SECRET,
    algorithms: [JWT_TOKEN_ALGO]
}).unless({ path: ["/login", "/register", "/token"]}))


app.get('/add', async (req, res) => {
    console.log("Add invoked");
    const { x, y } = req.body;
    const result = x + y;
    res.json({ result });
});


// /register and /login will be replaced with tiplink stuff - this is not permanent, just POC
app.post('/register', async (req, res) => {
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
});

// /register and /login will be replaced with tiplink stuff - this is not permanent, just POC
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({
        where: { email }
    });

    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ email }, ACCESS_TOKEN_SECRET, { expiresIn: "10m" });
        const refreshToken = jwt.sign({ email }, REFRESH_TOKEN_SECRET, { expiresIn: "1h" });
        res.json({ token, refreshToken });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});


// refresh token endpoint
app.post('/token', 
    expressjwt({ secret: REFRESH_TOKEN_SECRET, algorithms: [JWT_TOKEN_ALGO] }),
    async (req, res) => { 
        const email = (req as any)?.auth?.email;
        if (email == null) {
            return res.status(403);
        }
        const token = jwt.sign({ email }, ACCESS_TOKEN_SECRET, { expiresIn: "10m" });
        const refreshToken = jwt.sign({ email }, REFRESH_TOKEN_SECRET, { expiresIn: "1h" });
        return res.json({ token, refreshToken });
    }
);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
