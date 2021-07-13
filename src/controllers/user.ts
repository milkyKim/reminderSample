import { Request, Response } from 'express';
import User from '../models/User';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import config from '../config';
import { check, validationResult } from 'express-validator';
import { userService } from '../services';
import returnCode from '../library/returnCode';

/**
 * @api {post} /user/signup 회원가입
 * 
 * @apiVersion 1.0.0
 * @apiName SignUp
 * @apiGroup User
 * 
 * @apiHeaderExample {json} Header-Example:
 * {
 *  "Content-Type": "application/json"
 * }
 * 
 * @apiParamExample {json} Request-Example:
 * {
    "email": "whatisthis@naver.com",
    "password": "1234567",
    "name": "mk",
    "birth": "19980322",
    "phoneToken": "1" ,
    "phone": "01012345678"
 * }
 *
 * @apiSuccess {String} jwt
 * 
 * @apiSuccessExample {json} Success-Response:
 * 200 OK
 * {
 *  "status": 200,
 *  "message": "회원가입 성공"
 * }
 * 
 * @apiErrorExample Error-Response:
 * 400 아이디 중복
 * {
 *  "status": 400,
 *  "message": "이미 사용 중인 아이디입니다."
 * }
 */
const signUp = async (req: Request, res: Response) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      status: returnCode.BAD_REQUEST,
      errors: [{ msg: '요청바디가 없습니다.' }],
    });
  }
  const { name, birth, email, password, phoneToken, phone } = req.body;
  console.log(req.body);
  // 파라미터 확인
  if (!email || !password || !name || !birth || !phoneToken || !phone) {
    res.status(400).json({
      status: returnCode.BAD_REQUEST,
      message: '필수 정보를 입력하세요.',
    });
    return;
  }

  try {
    // 1. 유저가 중복일 경우
    let user = await userService.findUser({ email });
    if (user) {
      res.status(400).json({
        status: returnCode.BAD_REQUEST,
        msg: '유저가 이미 있습니다.',
      });
    }
    user = new User({
      email,
      password,
      name,
      birth,
      phoneToken,
      phone,
    });

    //Encrypt password
    const salt = await bcrypt.genSalt(10);
    const hashPwd = await bcrypt.hash(password, salt);
    await userService.saveUser({ email, password: hashPwd, name, birth, phoneToken, phone });

    res.json({
      status: returnCode.OK,
      message: '회원가입 성공',
    });
  } catch (err) {
    console.error(err.message);
    res.status(returnCode.INTERNAL_SERVER_ERROR).json({
      status: returnCode.INTERNAL_SERVER_ERROR,
      message: err.message,
    });
    return;
  }
};

/**
 * @api {post} /user/signin 로그인
 *
 * @apiVersion 1.0.0
 * @apiName SignIn
 * @apiGroup User
 *
 * @apiHeaderExample {json} Header-Example:
 * {
 *  "Content-Type": "application/json"
 * }
 *
 * @apiParamExample {json} Request-Example:
 * {
 *  "email": "keepin@gmail.com",
 *  "password": "1234abcd",
 * }
 *
 * @apiSuccess {String} jwt
 *
 * @apiSuccessExample {json} Success-Response:
 * 200 OK
 * {
 *  "status": 200,
 *  "message": "로그인 성공"   ,
 *  "data": {
 *    "jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjYwZTM0OTg5MzQ2MGVjMzk4ZWExZGM0NSIsImVtYWlsIjoiZmJkdWRkbjk3QG5hdmVyLmNvbSIsImlhdCI6MTYyNTYyMjg4NywiZXhwIjoxNjI1NjU4ODg3fQ.fgXLnokOo1HhPSInL25m35Bx5tLSha7XeH1vWIQ2dmA"
 *    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjYwZTM0OTg5MzQ2MGVjMzk4ZWExZGM0NSIsImVtYWlsIjoiZmJkdWRkbjk3QG5hdmVyLmNvbSIsImlhdCI6MTYyNTYyMjg4NywiZXhwIjoxNjI1NjU4ODg3fQ.fgXLnokOo1HhPSInL25m35Bx5tLSha7XeH1vWIQ2dmA"
 *    "name": "김키핀"
 *  }
 * }
 *
 * @apiErrorExample Error-Response:
 * 400 아이디 확인
 * {
 *  "status": 400,
 *  "message": "유저가 없습니다."
 * }
 * 400 비밀번호 확인
 * {
 *  "status": 400,
 *  "message": "비밀번호가 일치하지 않습니다."
 * }
 */
const signIn = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      status: returnCode.BAD_REQUEST,
      message: '요청바디가 없습니다.',
    });
  }
  const { email, password } = req.body;
  try {
    const user = await userService.findUser({ email });

    if (!user) {
      res.status(400).json({
        status: returnCode.BAD_REQUEST,
        message: '이메일/비밀번호를 다시 확인해주세요.',
      });
    }
    // Encrpyt password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      res.status(400).json({
        status: returnCode.BAD_REQUEST,
        message: '이메일/비밀번호를 다시 확인해주세요.',
      });
    }

    // Return jsonwebtoken
    const payload = {
      id: user._id,
      email: user.email,
    };

    const result = {
      accessToken: jwt.sign(payload, config.jwtSecret, { expiresIn: '7d' }),
      refreshToken: jwt.sign(payload, config.jwtSecret, { expiresIn: '7d' }),
    };

    // refreshToken을 DB에 저장
    const userInfo = await userService.saveRefreshToken({ email: payload.email, refreshToken: result.refreshToken });

    res.json({
      status: returnCode.OK,
      message: '로그인 성공',
      data: {
        jwt: result.accessToken,
        refreshToken: result.refreshToken,
        name: user.name,
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(returnCode.INTERNAL_SERVER_ERROR).json({
      status: returnCode.INTERNAL_SERVER_ERROR,
      message: err.message,
    });
    return;
  }
};

export default {
  signUp,
  signIn,
};
