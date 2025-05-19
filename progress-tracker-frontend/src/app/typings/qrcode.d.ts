/*  src/typings/qrcode.d.ts
    Minimal declaration so TypeScript knows the “qrcode” module exists. */
    declare module 'qrcode' {
        /** levels supported by the library */
        export type QRCodeErrorCorrectionLevel = 'L' | 'M' | 'Q' | 'H';
      
        /** we only need the promise‑based `toDataURL()` that angularx‑qrcode calls */
        export function toDataURL(
          text: string,
          options?: {
            errorCorrectionLevel?: QRCodeErrorCorrectionLevel;
            /** any extra options the lib accepts */
            [key: string]: any;
          }
        ): Promise<string>;
      }
      