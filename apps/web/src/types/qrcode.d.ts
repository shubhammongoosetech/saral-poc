declare module 'qrcode' {
  export function toString(value: string, options: { type: 'svg'; width: number }): Promise<string>;
}
