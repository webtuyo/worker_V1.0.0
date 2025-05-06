const TOTP_INTERVAL = 30; // 30 seconds time interval for TOTP

// Helper function to generate TOTP
export async function generateTOTP(secret, timestamp) {
  const encoder = new TextEncoder();

  // Convert the secret (Base32) to bytes
  const key = await convertSecretToBytes(secret);

  // Calculate the time step (number of 30-second intervals since epoch)
  const timeStep = Math.floor(timestamp / 1000 / TOTP_INTERVAL);

  // Convert time step to an 8-byte buffer
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(4, timeStep, false); // Set the lower 32 bits of the buffer

  // Create HMAC using the Web Crypto API
  const hmacKey = await crypto.subtle.importKey(
    'raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const hmac = await crypto.subtle.sign('HMAC', hmacKey, buffer);

  // Truncate the HMAC to get a 6-digit TOTP
  return truncateHMAC(new Uint8Array(hmac));
}

// Helper function to convert Base32 secret to bytes
async function convertSecretToBytes(secret) {
  const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = new Uint8Array(secret.length * 5 / 8);
  let buffer = 0;
  let bitsLeft = 0;
  let byteIndex = 0;

  for (let i = 0; i < secret.length; i++) {
    const val = base32Chars.indexOf(secret.charAt(i).toUpperCase());
    if (val === -1) {
      throw new Error('Invalid Base32 character');
    }

    buffer = (buffer << 5) | val;
    bitsLeft += 5;

    if (bitsLeft >= 8) {
      bytes[byteIndex++] = (buffer >> (bitsLeft - 8)) & 255;
      bitsLeft -= 8;
    }
  }

  return bytes;
}

// Helper function to truncate the HMAC result
function truncateHMAC(hmac) {
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0'); // Return a 6-digit TOTP
}

// Verify TOTP code (compares user-provided code with generated code)
export async function verifyTOTP(secret, userCode) {
  const currentTimestamp = Date.now();
  const generatedCode = await generateTOTP(secret, currentTimestamp);

  return generatedCode === userCode;
}

// Define the function
export async function hashPassword(password, salt) {
  try {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const saltBuffer = encoder.encode(salt);

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const hashBuffer = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 100000, // Replace PBKDF2_ITERATIONS with a specific number
        hash: 'SHA-256',
      },
      keyMaterial,
      256 // Length in bits
    );

    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
  } catch (error) {
    console.error('Error hashing password:', error);
  }
}
