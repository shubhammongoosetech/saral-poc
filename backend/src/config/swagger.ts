/**
 * SARAL — OpenAPI 3.0 Specification & Swagger UI Configuration
 */

import swaggerUi from 'swagger-ui-express';

export const swaggerDocument: Record<string, any> = {
  openapi: '3.0.3',
  info: {
    title: 'SARAL API — Cryptographic Key Management & Wallet',
    version: '1.0.0',
    description: `
**SARAL** is a Non-Custodial, Separation-of-Powers Cryptographic Key Management System with an Adaptive Multi-Asset Economic Security Layer.

### Core Security Architecture:
- **3-Domain Separation of Powers:** Keys are additively distributed across Foundation, Public, and Private domains with genuine Threshold MPC signing.
- **Shamir Secret Sharing (SSS) over F_n:** Internal threshold quorums (5-of-9) over the secp256k1 scalar field.
- **AES-256-GCM Authenticated Encryption:** Individual key shares are encrypted at rest with HKDF domain separation.
- **Dual Authentication & MFA:** Google OAuth 2.0 and Mobile Phone OTP authentication with mandatory two-step verification.
- **MSTC Testnet Integration:** Threshold MPC signing produces EVM-compliant signatures with Zero Private Key Reconstruction.
    `,
    contact: {
      name: 'SARAL Security Team',
      url: 'https://saral-network.org',
    },
  },
  servers: [
    {
      url: 'http://localhost:3001',
      description: 'Local Development Server',
    },
  ],
  tags: [
    { name: 'System', description: 'Health check and system diagnostics' },
    { name: 'Auth', description: 'Phone OTP, Google OAuth 2.0, MFA, and Work Schedule' },
    { name: 'Wallet', description: '3-Domain Shamir key generation, ready-to-sign checks, and MSTC Testnet signing' },
  ],
  components: {
    securitySchemes: {
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Provide JWT token received from phone verify or Google login. Format: `Bearer <token>`',
      },
    },
    schemas: {
      ErrorResponse: {
        type: 'object',
        properties: {
          error: { type: 'string', example: 'Invalid or expired OTP' },
        },
      },
      User: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid', example: 'e7353c7a-c5d8-48c4-9f5c-d9b46a586f2b' },
          phone: { type: 'string', example: '+919876543210' },
          googleId: { type: 'string', nullable: true, example: '109876543210987654321' },
          email: { type: 'string', nullable: true, example: 'user@example.com' },
          name: { type: 'string', nullable: true, example: 'Saral Operator' },
          authMethod: { type: 'string', enum: ['phone', 'google'], example: 'phone' },
          workStartTime: { type: 'string', example: '10:00' },
          workEndTime: { type: 'string', example: '18:00' },
          workLocation: { type: 'string', example: 'Mumbai, India' },
          mfaEnabled: { type: 'boolean', example: true },
          mfaVerified: { type: 'boolean', example: true },
          createdAt: { type: 'string', format: 'date-time' },
          updatedAt: { type: 'string', format: 'date-time' },
        },
      },
      Wallet: {
        type: 'object',
        properties: {
          walletAddress: { type: 'string', example: '0xbb4bef972449CAA8BB7626a5e41BcE6243e74c52' },
          publicKey: { type: 'string', example: '0x04a2c5f...e41' },
        },
      },
    },
  },
  paths: {
    '/health': {
      get: {
        tags: ['System'],
        summary: 'Service Health Check',
        description: 'Returns health status and current server timestamp.',
        responses: {
          200: {
            description: 'Server is healthy',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    status: { type: 'string', example: 'ok' },
                    service: { type: 'string', example: 'SARAL Backend' },
                    timestamp: { type: 'string', format: 'date-time' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/auth/phone/request-otp': {
      post: {
        tags: ['Auth'],
        summary: 'Request Phone OTP',
        description: 'Generates and sends a 6-digit one-time passcode for phone-based authentication.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['phone'],
                properties: {
                  phone: { type: 'string', example: '+919876543210' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'OTP sent successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'OTP sent' },
                    userId: { type: 'string', format: 'uuid' },
                    devOtp: { type: 'string', description: 'Available in dev mode for testing', example: '765985' },
                  },
                },
              },
            },
          },
          400: {
            description: 'Missing phone number',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/api/auth/phone/verify': {
      post: {
        tags: ['Auth'],
        summary: 'Verify Phone OTP',
        description: 'Validates phone OTP code and returns a signed JWT token.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['userId', 'code'],
                properties: {
                  userId: { type: 'string', format: 'uuid', example: 'e7353c7a-c5d8-48c4-9f5c-d9b46a586f2b' },
                  code: { type: 'string', example: '765985' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'OTP verified successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    token: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsIn...' },
                    user: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          400: {
            description: 'Invalid or expired OTP',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
        },
      },
    },
    '/api/auth/google': {
      post: {
        tags: ['Auth'],
        summary: 'Google OAuth Sign-In',
        description: 'Authenticates via Google credential token or development demo account.',
        requestBody: {
          required: false,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  idToken: { type: 'string', example: 'demo-google-token' },
                  demoEmail: { type: 'string', example: 'operator@saral-network.org' },
                  demoName: { type: 'string', example: 'Saral Operator' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Google authentication successful',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    token: { type: 'string', example: 'eyJhbGciOiJIUzI1NiIsIn...' },
                    user: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/auth/google/url': {
      get: {
        tags: ['Auth'],
        summary: 'Get Google OAuth2 Consent URL',
        description: 'Generates the Google OAuth 2.0 authorization redirect URL with openid, email, and profile scopes.',
        responses: {
          200: {
            description: 'Authorization URL generated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    url: { type: 'string', example: 'https://accounts.google.com/o/oauth2/v2/auth?...' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/auth/google/callback': {
      get: {
        tags: ['Auth'],
        summary: 'Google OAuth2 Redirect Callback',
        description: 'Receives the authorization code from Google, exchanges it for user identity, creates/updates the user, and redirects to frontend.',
        parameters: [
          { name: 'code', in: 'query', required: false, schema: { type: 'string' } },
          { name: 'error', in: 'query', required: false, schema: { type: 'string' } },
        ],
        responses: {
          302: { description: 'Redirects to frontend with JWT token' },
        },
      },
    },
    '/api/auth/me': {
      get: {
        tags: ['Auth'],
        summary: 'Get Current User Profile',
        description: 'Returns profile details for the authenticated user.',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'User profile retrieved',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    user: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
        },
      },
    },
    '/api/auth/me/schedule': {
      put: {
        tags: ['Auth'],
        summary: 'Update Work Schedule & Location',
        description: 'Saves active working hours (e.g. 10:00 to 18:00) and operational location for security policy enforcement.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['workStartTime', 'workEndTime', 'workLocation'],
                properties: {
                  workStartTime: { type: 'string', example: '10:00' },
                  workEndTime: { type: 'string', example: '18:00' },
                  workLocation: { type: 'string', example: 'Mumbai, India' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Schedule updated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'Schedule updated' },
                    user: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
        },
      },
    },
    '/api/auth/mfa/request': {
      post: {
        tags: ['Auth'],
        summary: 'Request 2-Step MFA Code',
        description: 'Sends a second-factor OTP code to the user’s registered or provided phone number.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: false,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  phone: { type: 'string', example: '+919876543210' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'MFA OTP dispatched',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'MFA OTP sent' },
                    phone: { type: 'string', example: '+919876543210' },
                    devOtp: { type: 'string', example: '042508' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
        },
      },
    },
    '/api/auth/mfa/verify': {
      post: {
        tags: ['Auth'],
        summary: 'Verify 2-Step MFA Code',
        description: 'Validates MFA passcode and marks user account as MFA verified.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['code'],
                properties: {
                  code: { type: 'string', example: '042508' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'MFA verified',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'MFA verified' },
                    user: { $ref: '#/components/schemas/User' },
                  },
                },
              },
            },
          },
          400: {
            description: 'Invalid MFA code',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/ErrorResponse' } } },
          },
          401: { description: 'Unauthorized' },
        },
      },
    },
    '/api/wallet/generate': {
      post: {
        tags: ['Wallet'],
        summary: 'Generate 3-Domain SSS Wallet',
        description: `
Generates a new secp256k1 keypair using ethers. The private key is decomposed into 3 domains:
1. **Public Domain**
2. **Institutional Domain**
3. **Sovereign Domain**

Each domain is then split via Shamir's Secret Sharing into 9 node shares with a threshold of 5 (k=5, n=9). Individual shares are AES-256-CBC encrypted and saved to PostgreSQL.
        `,
        security: [{ BearerAuth: [] }],
        responses: {
          201: {
            description: 'Wallet successfully generated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'Wallet generated successfully' },
                    walletAddress: { type: 'string', example: '0xbb4bef972449CAA8BB7626a5e41BcE6243e74c52' },
                    publicKey: { type: 'string', example: '0x04a2c5f...e41' },
                  },
                },
              },
            },
          },
          200: {
            description: 'Existing wallet returned if already generated',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'Wallet already exists' },
                    walletAddress: { type: 'string', example: '0xbb4bef972449CAA8BB7626a5e41BcE6243e74c52' },
                    publicKey: { type: 'string', example: '0x04a2c5f...e41' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
        },
      },
    },
    '/api/wallet': {
      get: {
        tags: ['Wallet'],
        summary: 'Get Wallet Details',
        description: 'Returns the user’s Ethereum/MSTC wallet address and uncompressed public key.',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'Wallet details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Wallet' },
              },
            },
          },
          404: { description: 'Wallet not generated yet' },
          401: { description: 'Unauthorized' },
        },
      },
    },
    '/api/wallet/ready-to-sign': {
      post: {
        tags: ['Wallet'],
        summary: 'Ready-to-Sign Validation',
        description: 'Loads encrypted key shares from all 3 domains, verifies threshold (>=5 shares per domain), reconstructs key in ephemeral memory, and confirms public key derivation match.',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'Verification successful',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    ready: { type: 'boolean', example: true },
                    walletAddress: { type: 'string', example: '0xbb4bef972449CAA8BB7626a5e41BcE6243e74c52' },
                    domainsVerified: {
                      type: 'array',
                      items: { type: 'string' },
                      example: ['public', 'institutional', 'sovereign'],
                    },
                    sharesPerDomain: { type: 'number', example: 9 },
                    threshold: { type: 'number', example: 5 },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'Wallet not found' },
        },
      },
    },
    '/api/wallet/send': {
      post: {
        tags: ['Wallet'],
        summary: 'Execute MSTC Testnet Payment',
        description: 'Builds an EIP-1559/Type-2 transaction, reconstructs the private key on-demand to sign, and broadcasts it to the MSTC testnet RPC to produce a genuine transaction hash (txHash).',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['to', 'value'],
                properties: {
                  to: { type: 'string', example: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e' },
                  value: { type: 'string', example: '0.01' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Transaction broadcasted/signed',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'Payment executed on MSTC Testnet' },
                    txHash: { type: 'string', example: '0xda5bdaad8959450b4d2740c9062b6e489a35d648f5da91541526c392bb9a4ea4' },
                    from: { type: 'string', example: '0xbb4bef972449CAA8BB7626a5e41BcE6243e74c52' },
                    to: { type: 'string', example: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e' },
                    value: { type: 'string', example: '0.01 MSTC' },
                    chainId: { type: 'number', example: 1337 },
                    status: { type: 'string', example: 'confirmed' },
                    isLiveBroadcast: { type: 'boolean', example: false },
                  },
                },
              },
            },
          },
          400: { description: 'Invalid parameters' },
          401: { description: 'Unauthorized' },
        },
      },
    },
    '/api/wallet/sign': {
      post: {
        tags: ['Wallet'],
        summary: 'Sign Custom 32-Byte Hash',
        description: 'Reconstructs the private key from threshold shares across Public, Institutional, and Sovereign domains, and signs a custom 32-byte digest (ECDSA secp256k1).',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['txHash'],
                properties: {
                  txHash: { type: 'string', example: '0xda5bdaad8959450b4d2740c9062b6e489a35d648f5da91541526c392bb9a4ea4' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Hash signed successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'Signed successfully' },
                    signature: { type: 'string', example: '0x6886c54e0eb339011e0fb57e9442...' },
                    walletAddress: { type: 'string', example: '0xbb4bef972449CAA8BB7626a5e41BcE6243e74c52' },
                    publicKey: { type: 'string', example: '0x04a2c5f...e41' },
                  },
                },
              },
            },
          },
          400: { description: 'Invalid txHash format' },
          401: { description: 'Unauthorized' },
        },
      },
    },
  },
};

const customCss = `
  .swagger-ui .topbar { display: none; }
  .swagger-ui .info { margin: 25px 0; }
  .swagger-ui .info .title { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; font-weight: 700; color: #111827; }
  .swagger-ui .scheme-container { background: #fafafa; box-shadow: none; border-bottom: 1px solid #e5e7eb; padding: 15px 0; }
  .swagger-ui .btn.authorize { color: #111827; border-color: #111827; }
  .swagger-ui .btn.authorize svg { fill: #111827; }
`;

export function setupSwagger(app: any) {
  // Serve Swagger UI on /docs and /api/docs
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
    customCss,
    customSiteTitle: 'SARAL API Documentation',
  }));

  app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
    customCss,
    customSiteTitle: 'SARAL API Documentation',
  }));

  // JSON raw schema endpoint
  app.get('/api/docs.json', (_req: any, res: any) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerDocument);
  });
}

export default swaggerDocument;
