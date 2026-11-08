import 'dotenv/config';

const production = process.env.NODE_ENV === 'production';

function requiredInProduction(name, fallback) {
  const value = process.env[name] || fallback;
  if (production && !process.env[name]) {
    throw new Error(`${name} must be set in production`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT || 3000),
  production,
  accessSecret: requiredInProduction('JWT_ACCESS_SECRET', 'development-access-secret-change-me'),
  refreshSecret: requiredInProduction('JWT_REFRESH_SECRET', 'development-refresh-secret-change-me'),
  accessTtl: process.env.ACCESS_TOKEN_TTL || '15m',
  refreshTtl: process.env.REFRESH_TOKEN_TTL || '7d',
  refreshCookie: 'refresh_token'
};
