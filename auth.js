import { createResponse } from "./utils.js";
import { verifyTOTP, hashPassword } from "./otp.js";
import { isBlocked, incrementAttempts,resetAttempts } from "./database.js";

// Authenticate user via OTP and password
export async function authenticateUser(env, request) {
    const ip =
      request.headers.get('CF-Connecting-IP') ||
      request.headers.get('X-Forwarded-For') ||
      '0.0.0.0';

    if (await isBlocked(env, ip)) {
      return createResponse('Too many attempts. Try again later.', { status: 429 }, request, env);
    }

    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      await incrementAttempts(env, ip);
      // // // console.log("inv cred 1:", );
      return createResponse('Invalid credentials!', { status: 401 }, request, env);
    }

    const base64Credentials = authHeader.slice('Basic '.length);
    let decodedCredentials;
    try {
      decodedCredentials = atob(base64Credentials);
    } catch (err) {
      await incrementAttempts(env, ip);
      // // // console.log("inv cred 2. Err:", err);
      return createResponse('Invalid credentials:', { status: 401 }, request, env);
    }

    const [otp, password] = decodedCredentials.split(':');

    if (!otp || !password) {
      await incrementAttempts(env, ip);
      // // console.log("inv cred 3. otp, password:", otp, password)
      return createResponse('Invalid credentials', { status: 401 }, request, env);
    }
    // // // // console.log("otp, passwor:", otp, password);

    const isOtpValid = await verifyTOTP(env.TFA, otp);
    const hashedPassword = await hashPassword(password, env.SALT);
    // console.log("password:", password, "hashedpassword:", hashedPassword, "store hp:", STORED_PASSWORD_HASH)
    const isPasswordValid = hashedPassword === env.HASHP;

    if (!isOtpValid || !isPasswordValid) {
      await incrementAttempts(env, ip);
      // // // console.log("inv cred 4. IsValidOTP, isPassValid:", isOtpValid, isPasswordValid);
      // // // console.log("inv4. Hashed password: ", hashedPassword);
      // // // console.log("inv4. Store password hash:", env.HASHP);
      return createResponse('Invalid credentials', { status: 401 }, request, env);
    }

    // Reset failed attempts on successful login
    await resetAttempts(env, ip);

    return null; // Indicate success
  }
