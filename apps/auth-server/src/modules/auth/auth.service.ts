import {
  checkOtpCooldown,
  linkAccount,
  requestPhoneOtp,
  verifyGoogleToken,
  verifyPhoneOtp,
} from '../../services/accountService';

export class AuthService {
  public checkOtpCooldown = checkOtpCooldown;
  public requestPhoneOtp = requestPhoneOtp;
  public verifyPhoneOtp = verifyPhoneOtp;
  public verifyGoogleToken = verifyGoogleToken;
  public linkAccount = linkAccount;
}

export const authService = new AuthService();

