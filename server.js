require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const accountSid = process.env.ACCOUNT_SID;
const authToken = process.env.AUTH_TOKEN;
const cookieParser = require('cookie-parser');
const client = require('twilio')(accountSid, authToken);
const cors = require('cors');
const jwt = require('jsonwebtoken');
const JWT_AUTH_TOKEN = process.env.JWT_AUTH_TOKEN;
const JWT_REFRESH_TOKEN = process.env.JWT_REFRESH_TOKEN;
let refreshTokens = [];
const smsKey = process.env.SMS_SECRET_KEY;

const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(cookieParser());

app.post('/sendOTP', (req, res) => {
  const phone = req.body.phone;
  const otp = Math.floor(10000 + Math.random() * 900000);
  const ttl = 2 * 60 * 1000;
  const expires = Date.now() + ttl;
  const data = `${phone}.${otp}.${expires}`;
  const hash = crypto.createHmac('sha256', smsKey).update(data).digest('hex');
  const fullhash = `${hash}.${expires}`;

  client.messages
    .create({
      body: `Your One Time Password is ${otp}`,
      from: +16693221413,
      to: phone,
    })
    .then((messages) => console.log(messages))
    .catch((error) => console.log(error));

  res.status(200).send({ phone, hash: fullhash, otp });
});

app.post('/verifyOTP', (req, res) => {
  const phone = req.body.phone;
  const hash = req.body.hash;
  const otp = req.body.otp;
  let [hashValue, expires] = hash.split('.');

  let now = Date.now();
  if (now > parseInt(expires)) {
    return res.status(504).send({ msg: 'Timeout. Please try again' });
  }

  let data = `${phone}.${otp}.${expires}`;
  let newCalculatedHash = crypto
    .createHmac('sha256', smsKey)
    .update(data)
    .digest('hex');
  if (newCalculatedHash === hashValue) {
    // refreshTokens.push(refreshToken);
    const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, {
      expiresIn: '30s',
    });
    const refreshToken = jwt.sign({ data: phone }, JWT_REFRESH_TOKEN, {
      expiresIn: '1y',
    });
    refreshTokens.push(refreshToken);

    res
      .status(202)
      .cookie('accessToken', accessToken, {
        expires: new Date(new Date().getTime() + 30 * 1000),
        sameSite: 'strict',
        httpOnly: true,
      })
      .cookie('refreshToken', refreshToken, {
        expires: new Date(new Date().getTime() + 31557600000),
        sameSite: 'strict',
        httpOnly: true,
      })
      .cookie('authSession', true, {
        expires: new Date(new Date().getTime() + 30 * 1000),
        sameSite: 'strict',
      })
      .cookie('refreshTokenID', true, {
        expires: new Date(new Date().getTime() + 31557600000),
        sameSite: 'strict',
      })
      .send({ msg: 'Device verified' });
  } else {
    return res.status(400).send({ verification: false, msg: `Incorrect OTP` });
  }
});

async function authenticateUser(req, res, next) {
  const accessToken = req.cookies.accessToken;

  jwt.verify(accessToken, JWT_AUTH_TOKEN, async (err, phone) => {
    if (phone) {
      req.phone = phone;
      next();
    } else if (err.message === 'TokenExpiredError') {
      return res.status(403).send({
        success: false,
        msg: 'Access token expired',
      });
    } else {
      console.log(err);
      return res.status(403).send({ err, msg: 'User not authenticated' });
    }
  });
}

app.post('/refresh', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken)
    return res
      .status(403)
      .send({ message: 'Refresh token not found, login again' });
  if (!refreshTokens.includes(refreshToken))
    return res
      .status(403)
      .send({ message: 'Refresh token blocked, login again' });

  jwt.verify(refreshToken, JWT_REFRESH_TOKEN, (err, phone) => {
    if (!err) {
      const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, {
        expiresIn: '30s',
      });
      return res
        .status(200)
        .cookie('accessToken', accessToken, {
          expires: new Date(new Date().getTime() + 30 * 1000),
          sameSite: 'strict',
          httpOnly: true,
        })
        .cookie('authSession', true, {
          expires: new Date(new Date().getTime() + 30 * 1000),
          sameSite: 'strict',
        })
        .send({ previousSessionExpired: true, success: true });
    } else {
      return res.status(403).send({
        success: false,
        msg: 'Invalid refresh token',
      });
    }
  });
});

app.get('/logout', (req, res) => {
  res
    .clearCookie('refreshToken')
    .clearCookie('accessToken')
    .clearCookie('authSession')
    .clearCookie('refreshTokenID')
    .send('logout');
});
app.listen(4000);
