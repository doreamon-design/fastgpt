import type { NextRequest } from 'next/server';
import { NextResponse } from 'next/server';
import { setCookie } from '@/service/utils/tools';
// import { generateToken } from '@fastgpt/support/user/tools'
import { connectToDatabase } from '@/service/mongo';
// import { MongoUser } from '@fastgpt/support/user/schema'
// import * as connect from '@znode/connect'
import doreamon from '@zodash/doreamon';
import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import mongoose from 'mongoose';
import { hashStr } from '@fastgpt/common/tools/str';

type User = any;

async function verify(secret: string, token: string): Promise<User> {
  const { payload } = await jwtVerify(token, new TextEncoder().encode(secret));
  // run some checks on the returned payload, perhaps you expect some specific values

  // if its all good, return it, or perhaps just return a boolean
  return payload as any;
}

const generateToken = async (userId: string) => {
  const key = new TextEncoder().encode(process.env.SECRET_KEY);
  const jwt = new SignJWT({
    userId,
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7
  });
  const token = await jwt
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setIssuer('urn:example:issuer')
    .setAudience('urn:example:audience')
    .setExpirationTime('2h')
    .sign(key);
  return token;
};

const UserSchema = new mongoose.Schema({
  username: {
    // 可以是手机/邮箱，新的验证都只用手机
    type: String,
    required: true,
    unique: true // 唯一
  },
  password: {
    type: String,
    required: true,
    set: (val: string) => hashStr(val),
    get: (val: string) => hashStr(val),
    select: false
  }
});

mongoose.set('strictQuery', true);
mongoose.connect(process.env.MONGODB_URI as string, {
  bufferCommands: true,
  maxConnecting: Number(process.env.DB_MAX_LINK || 5),
  maxPoolSize: Number(process.env.DB_MAX_LINK || 5),
  minPoolSize: 2
});

// This function can be marked `async` if using `await` inside
export async function middleware(request: NextRequest) {
  const connectToken = request.headers.get('X-Connect-Token');
  const secretKey = process.env.SECRET_KEY;
  // const res = NextResponse.next()
  console.log('X-Connect-Token:', request.headers.get('X-Connect-Token'));
  if (!!connectToken) {
    try {
      // const connectUser = connect.decodeUser(secretKey!, connectToken!);
      const connectUser = await verify(secretKey!, connectToken!);
      console.log('auth connect user:', connectUser);

      // await connectToDatabase();
      // let authUser = await MongoUser.findOne({
      //   username: connectUser.email,
      // });
      // if (!authUser) {
      //   authUser = await MongoUser.create({
      //     username: connectUser.email,
      //     password: doreamon.random.secret(),
      //     avatar: connectUser.avatar,
      //   });
      // }

      const MongoUser = mongoose.model('user', UserSchema);
      let authUser = await MongoUser.findOne({
        username: connectUser.email
      });
      if (!authUser) {
        authUser = await MongoUser.create({
          username: connectUser.email,
          password: doreamon.random.secret(),
          avatar: connectUser.avatar
        });
      }

      // const token = await generateToken(authUser._id);
      const token = await generateToken(authUser.id);
      // setCookie(res, token);

      const res = NextResponse.next();
      res.headers.set(
        'Set-Cookie',
        `token=${token}; Path=/; HttpOnly; Max-Age=604800; Samesite=None; Secure;`
      );
      return res;
    } catch (error) {
      console.log('[middlew.auth] error:', error);
    }
  }

  // request.headers.set("Cookie", "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2NTJhZWU0Mjc3M2MwYzIyYjM0ZDEwZWYiLCJleHAiOjE2OTc5NDkyMDYsImlhdCI6MTY5NzM0NDQwNn0.1vfM03UeQK51vIGMmbFdEw4Fdt6rruiTWGwehDwOUsU")
  return;
}

// See "Matching Paths" below to learn more
// export const config = {
//   matcher: '/(.*)',
//   // runtime: 'nodejs',
// }
